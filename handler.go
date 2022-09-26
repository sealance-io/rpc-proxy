package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/gochain/gochain/v3/goclient"
	"github.com/gochain/gochain/v3/rpc"
	"github.com/treeder/gotils/v2"
)

type myTransport struct {
	blockRangeLimit uint64 // 0 means none

	matcher
	limiters

	latestBlock
}

type ModifiedRequest struct {
	Path       string
	RemoteAddr string // Original IP, not CloudFlare or load balancer.
	ID         json.RawMessage
	Params     []json.RawMessage
}

func isBatch(msg []byte) bool {
	for _, c := range msg {
		if c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d {
			continue
		}
		return c == '['
	}
	return false
}

// getIP returns the original IP address from the request, checking special headers before falling back to RemoteAddr.
func getIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// Trim off any others: A.B.C.D[,X.X.X.X,Y.Y.Y.Y,]
		return strings.SplitN(ip, ",", 1)[0]
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

func parseRequests(r *http.Request) (string, []string, []ModifiedRequest, error) {
	var res []ModifiedRequest
	var methods []string
	ip := getIP(r)
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(body)) // must be done, even when err
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to read body: %v", err)
		}
		methods, res, err = parseMessage(body, ip)
		if err != nil {
			return "", nil, nil, err
		}
	}
	if len(res) == 0 {
		methods = append(methods, r.URL.Path)
		res = append(res, ModifiedRequest{
			Path:       r.URL.Path,
			RemoteAddr: ip,
		})
	}
	return ip, methods, res, nil
}

func parseMessage(body []byte, ip string) (methods []string, res []ModifiedRequest, err error) {
	type rpcRequest struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if isBatch(body) {
		var arr []rpcRequest
		err := json.Unmarshal(body, &arr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse JSON batch request: %v", err)
		}
		for _, t := range arr {
			methods = append(methods, t.Method)
			res = append(res, ModifiedRequest{
				ID:         t.ID,
				Path:       t.Method,
				RemoteAddr: ip,
				Params:     t.Params,
			})
		}
	} else {
		var t rpcRequest
		err := json.Unmarshal(body, &t)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse JSON request: %v", err)
		}
		methods = append(methods, t.Method)
		res = append(res, ModifiedRequest{
			ID:         t.ID,
			Path:       t.Method,
			RemoteAddr: ip,
			Params:     t.Params,
		})
	}
	return methods, res, nil
}

const (
	jsonRPCTimeout       = -32000
	jsonRPCUnavailable   = -32601
	jsonRPCInvalidParams = -32602
	jsonRPCInternal      = -32603
)

type ErrResponse struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func jsonRPCError(id json.RawMessage, jsonCode int, msg string) interface{} {

	resp := ErrResponse{
		Version: "2.0",
		ID:      id,
	}
	resp.Error.Code = jsonCode
	resp.Error.Message = msg
	return resp
}

func jsonRPCUnauthorized(id json.RawMessage, method string) interface{} {
	return jsonRPCError(id, jsonRPCUnavailable, "You are not authorized to make this request: "+method)
}

func jsonRPCLimit(id json.RawMessage) interface{} {
	return jsonRPCError(id, jsonRPCTimeout, "You hit the request limit")
}

func jsonRPCBlockRangeLimit(id json.RawMessage, blocks, limit uint64) interface{} {
	return jsonRPCError(id, jsonRPCInvalidParams, fmt.Sprintf("Requested range of blocks (%d) is larger than limit (%d).", blocks, limit))
}

// jsonRPCResponse returns a JSON response containing v, or a plaintext generic
// response for this httpCode and an error when JSON marshalling fails.
func jsonRPCResponse(httpCode int, v interface{}) (*http.Response, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return &http.Response{
			Body:       io.NopCloser(strings.NewReader(http.StatusText(httpCode))),
			StatusCode: httpCode,
		}, fmt.Errorf("failed to serialize JSON: %v", err)
	}
	return &http.Response{
		Body:       io.NopCloser(bytes.NewReader(body)),
		StatusCode: httpCode,
	}, nil
}

type AddHeaderTransport struct {
	T http.RoundTripper
}

func (adt *AddHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("content-type", "application/JSON")
	req.Header.Add("X-Access-Key", "<REDACTED>")
	return adt.T.RoundTrip(req)
}

func NewAddHeaderTransport(T http.RoundTripper) *AddHeaderTransport {
	if T == nil {
		T = http.DefaultTransport
	}
	return &AddHeaderTransport{T}
}

type SimpleResult struct {
	ID      int64  `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
	Result  string `json:"result"`
}

const tenderlyAccount string = "<REDACTED>"
const tenderlyProject string = "<REDACTED>"
const tenderlyfork string = "<REDACTED>"

var tenderlyApiGetForkUri string = fmt.Sprintf("https://api.tenderly.co/api/v1/account/%s/project/%s/fork/%s", tenderlyAccount, tenderlyProject, tenderlyfork)
var tenderlyApiGetSimulationTemplateUri string = tenderlyApiGetForkUri + "/simulation/%s"
var tenderlyRpcUri string = fmt.Sprintf("https://rpc.tenderly.co/fork/%s", tenderlyfork)

func indexTenderly() {
	log.SetFlags(0)
	tenderly := http.Client{Transport: NewAddHeaderTransport(nil)}
	respTenderly, err := tenderly.Get(tenderlyApiGetForkUri)
	if err != nil {
		log.Fatal(err)
	}
	data, err := io.ReadAll(respTenderly.Body)
	respTenderly.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	tenderlyFork := new(TenderlyFork)
	if err := json.Unmarshal(data, &tenderlyFork); err != nil {
		log.Printf("The trick has failed! %v", err)
	}
	log.Printf("Tenderly ForkId=%s, first_block=%d, GlobalHead=%s\n", tenderlyFork.SimulationFork.ID, tenderlyFork.SimulationFork.BlockNumber, tenderlyFork.SimulationFork.GlobalHead)

	tenderly = http.Client{Transport: NewAddHeaderTransport(nil)}
	payload := strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "eth_blockNumber",
		"params": [],
		"id": 0
	}`)
	respTenderly, err = tenderly.Post(tenderlyRpcUri, "application/json", payload)
	if err != nil {
		log.Fatal(err)
	}
	data, err = io.ReadAll(respTenderly.Body)
	respTenderly.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	result := new(SimpleResult)
	if err := json.Unmarshal(data, &result); err != nil {
		log.Fatal(err)
	}
	firstBlock := tenderlyFork.SimulationFork.BlockNumber
	lastBlock, err := strconv.ParseInt(result.Result[2:], 16, 32)
	if err != nil {
		fmt.Println(err)
	}
	log.Printf("Tenderly first_block=%d, last_block=%d", firstBlock, lastBlock)

	headBlockHex := ""
	for currBlock := lastBlock; currBlock >= firstBlock; currBlock-- {
		currBlockHex := "0x" + strconv.FormatInt(currBlock, 16)
		payload := strings.NewReader(fmt.Sprintf(`{
		"jsonrpc": "2.0",
		"method": "eth_getBlockByNumber",
		"params": ["%s", false],
		"id": 0
	}`, currBlockHex))
		respTenderly, err = tenderly.Post(tenderlyRpcUri, "application/json", payload)
		if err != nil {
			log.Fatal(err)
		}
		data, err = io.ReadAll(respTenderly.Body)
		respTenderly.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
		block := new(Block)
		if err := json.Unmarshal(data, &block); err != nil {
			log.Fatal(err)
		}
		if headBlockHex != "" {
			log.Default().Printf(`cache["%s"] = "%s"`, headBlockHex, block.Result.Hash)
		}
		headBlockHex = currBlockHex
	}

	// var currSimulationID = tenderlyFork.SimulationFork.GlobalHead
	// var headBlockNumber string = ""

	// for {
	// 	getSimulationURI := fmt.Sprintf("tenderlyApiGetSimulationTemplateUri", currSimulationID)
	// 	respTenderly, err = tenderly.Get(getSimulationURI)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	data, err = io.ReadAll(respTenderly.Body)
	// 	respTenderly.Body.Close()
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	tenderlySimulation := new(TenderlySimulation)
	// 	if err := json.Unmarshal(data, &tenderlySimulation); err != nil {
	// 		log.Printf("The trick has failed! %v", err)
	// 	}
	// 	//log.Printf("simulation %s is part of block %s\n", tenderlySimulation.Simulation.ID, tenderlySimulation.Simulation.BlockHeader.Number)
	// 	payload := strings.NewReader(fmt.Sprintf(`{
	// 	"jsonrpc": "2.0",
	// 	"method": "eth_getBlockByNumber",
	// 	"params": ["%s", false],
	// 	"id": 0
	// }`, tenderlySimulation.Simulation.BlockHeader.Number))
	// 	respTenderly, err = tenderly.Post(tenderlyRpcUri, "application/json", payload)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	data, err = io.ReadAll(respTenderly.Body)
	// 	respTenderly.Body.Close()
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	block := new(Block)
	// 	if err := json.Unmarshal(data, &block); err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	//log.Printf("simulation %s is part of block with hash %s\n", tenderlySimulation.Simulation.ID, block.Result.Hash)
	// 	if headBlockNumber != "" {
	// 		log.Default().Printf(`cache["%s"] = "%s"`, headBlockNumber, block.Result.Hash)
	// 	}
	// 	headBlockNumber = tenderlySimulation.Simulation.BlockHeader.Number
	// 	if tenderlySimulation.Simulation.ParentID == "" || tenderlySimulation.Simulation.BlockHeader.Number == "0x" + strconv.FormatInt(tenderlyFork.SimulationFork.BlockNumber, 16) {
	// 		break
	// 	}
	// 	currSimulationID = tenderlySimulation.Simulation.ParentID
	//}
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(bytes), nil
}

func (t *myTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if reqID := middleware.GetReqID(req.Context()); reqID != "" {
		ctx = gotils.With(ctx, "requestID", reqID)
	}

	ip, methods, parsedRequests, err := parseRequests(req)
	if err != nil {
		gotils.L(ctx).Error().Printf("Failed to parse requests: %v", err)
		resp, err := jsonRPCResponse(http.StatusBadRequest, jsonRPCError(json.RawMessage("1"), jsonRPCInvalidParams, err.Error()))
		if err != nil {
			gotils.L(ctx).Error().Printf("Failed to construct invalid params response: %v", err)
		}
		return resp, nil
	}

	ctx = gotils.With(ctx, "remoteIp", ip)
	ctx = gotils.With(ctx, "methods", methods)
	errorCode, resp := t.block(ctx, parsedRequests)
	if resp != nil {
		resp, err := jsonRPCResponse(errorCode, resp)
		if err != nil {
			gotils.L(ctx).Error().Printf("Failed to construct a response: %v", err)
		}
		return resp, nil
	}

	gotils.L(ctx).Debug().Println("Forwarding request")
	//req.Host = req.RemoteAddr //workaround for CloudFlare

	reqDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		gotils.L(ctx).Error().Printf("Warning while logging the request! %v", err)
	} else {
		gotils.L(ctx).Debug().Printf("REQUEST:\n%s", string(reqDump))
	}

	remoteResp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		gotils.L(ctx).Error().Printf("Oh no! %v", err)
	} else if len(methods) > 1 && methods[0] == "eth_getBlockByNumber" && methods[1] == "eth_getBlockByNumber" {
		data, err := io.ReadAll(remoteResp.Body)
		remoteResp.Body.Close()
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data)) // must be done, even when err
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		blocks := make([]ExtendedBlock, 0)
		if err := json.Unmarshal(data, &blocks); err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		for i, block := range blocks {
			blocks[i].Result.ParentHash = block.Result.Hash
			if len(block.Result.Transactions) == 1 && block.Result.Transactions[0].Hash == "0xc5b2c658f5fa236c598a6e7fbf7f21413dc42e2a41dd982eb772b30707cba2eb" {
				blocks[i].Result.ParentHash, err = randomHex(32)
				if err != nil {
					gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
				}
				blocks[i].Result.Transactions = block.Result.Transactions[1:]
			}
			for i := range block.Result.Transactions {
				block.Result.Transactions[i].TransactionIndex = "0x" + strconv.FormatInt(int64(i), 16)
			}
		}

		data, err = json.Marshal(blocks)
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		newContentSize := int64(len(data))
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data))
		remoteResp.ContentLength = newContentSize
		remoteResp.Header.Set("Content-length", strconv.FormatInt(newContentSize, 10))
	} else if len(methods) == 1 && methods[0] == "eth_getBlockByNumber" {
		verbose, err := strconv.ParseBool(string(parsedRequests[0].Params[1]))
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		data, err := io.ReadAll(remoteResp.Body)
		remoteResp.Body.Close()
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data)) // must be done, even when err
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		if verbose {
			block := new(ExtendedBlock)
			if err := json.Unmarshal(data, &block); err != nil {
				gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
			}
			block.Result.ParentHash = block.Result.Hash
			if len(block.Result.Transactions) == 1 && block.Result.Transactions[0].Hash == "0xc5b2c658f5fa236c598a6e7fbf7f21413dc42e2a41dd982eb772b30707cba2eb" {
				block.Result.ParentHash, err = randomHex(32)
				if err != nil {
					gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
				}
				block.Result.Transactions = block.Result.Transactions[1:]
			}
			for i := range block.Result.Transactions {
				block.Result.Transactions[i].TransactionIndex = "0x" + strconv.FormatInt(int64(i), 16)
			}
			data, err = json.Marshal(block)
			if err != nil {
				gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
			}
			newContentSize := int64(len(data))
			remoteResp.Body = io.NopCloser(bytes.NewBuffer(data))
			remoteResp.ContentLength = newContentSize
			remoteResp.Header.Set("Content-length", strconv.FormatInt(newContentSize, 10))
		} else {
			block := new(Block)
			if err := json.Unmarshal(data, &block); err != nil {
				gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
			}
			block.Result.ParentHash = block.Result.Hash
			if len(block.Result.Transactions) == 1 && block.Result.Transactions[0] == "0xc5b2c658f5fa236c598a6e7fbf7f21413dc42e2a41dd982eb772b30707cba2eb" {
				block.Result.ParentHash, err = randomHex(32)
				if err != nil {
					gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
				}
				block.Result.Transactions = []string{} //make([]string, 0)
			}
			data, err = json.Marshal(block)
			if err != nil {
				gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
			}
			newContentSize := int64(len(data))
			remoteResp.Body = io.NopCloser(bytes.NewBuffer(data))
			remoteResp.ContentLength = newContentSize
			remoteResp.Header.Set("Content-length", strconv.FormatInt(newContentSize, 10))

		}
	} else if len(methods) > 1 && methods[0] == "eth_getTransactionReceipt" && methods[1] == "eth_getTransactionReceipt" {
		data, err := io.ReadAll(remoteResp.Body)
		remoteResp.Body.Close()
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data)) // must be done, even when err
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		receipts := make([]TransactionReceipt, 0)
		if err := json.Unmarshal(data, &receipts); err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		for i, receipt := range receipts {
			for j := range receipt.Result.Logs {
				receipts[i].Result.Logs[j].LogIndex = "0x" + strconv.FormatInt(int64(j), 16)
			}
		}

		data, err = json.Marshal(receipts)
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		newContentSize := int64(len(data))
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data))
		remoteResp.ContentLength = newContentSize
		remoteResp.Header.Set("Content-length", strconv.FormatInt(newContentSize, 10))
	} else if len(methods) == 1 && methods[0] == "eth_getTransactionReceipt" {
		data, err := io.ReadAll(remoteResp.Body)
		remoteResp.Body.Close()
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data)) // must be done, even when err
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		receipt := new(TransactionReceipt)
		if err := json.Unmarshal(data, &receipt); err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		for j := range receipt.Result.Logs {
			receipt.Result.Logs[j].LogIndex = "0x" + strconv.FormatInt(int64(j), 16)
		}
		data, err = json.Marshal(receipt)
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		newContentSize := int64(len(data))
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data))
		remoteResp.ContentLength = newContentSize
		remoteResp.Header.Set("Content-length", strconv.FormatInt(newContentSize, 10))
	} else if len(methods) == 1 && methods[0] == "eth_getLogs" {
		data, err := io.ReadAll(remoteResp.Body)
		remoteResp.Body.Close()
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data)) // must be done, even when err
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		logs := new(EthLogs)
		if err := json.Unmarshal(data, &logs); err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		for j := range logs.Result {
			logs.Result[j].LogIndex = "0x" + strconv.FormatInt(int64(j), 16)
		}
		data, err = json.Marshal(logs)
		if err != nil {
			gotils.L(ctx).Error().Printf("The trick has failed! %v", err)
		}
		newContentSize := int64(len(data))
		remoteResp.Body = io.NopCloser(bytes.NewBuffer(data))
		remoteResp.ContentLength = newContentSize
		remoteResp.Header.Set("Content-length", strconv.FormatInt(newContentSize, 10))
	}

	if remoteResp != nil {
		dumpResponse(ctx, remoteResp, true)
	}

	return remoteResp, err
}

func dumpResponse(ctx context.Context, resp *http.Response, body bool) {
	respDump, err := httputil.DumpResponse(resp, body)
	if err != nil {
		gotils.L(ctx).Error().Printf("Warning while logging the response! %v", err)
	} else {
		gotils.L(ctx).Debug().Printf("RESPONSE:\n%s", string(respDump))
	}
}

// block returns a response only if the request should be blocked, otherwise it returns nil if allowed.
func (t *myTransport) block(ctx context.Context, parsedRequests []ModifiedRequest) (int, interface{}) {
	var union *blockRange
	for _, parsedRequest := range parsedRequests {
		ctx = gotils.With(ctx, "ip", parsedRequest.RemoteAddr)
		if allowed, _ := t.AllowVisitor(parsedRequest); !allowed {
			gotils.L(ctx).Info().Print("Request blocked: Rate limited")
			return http.StatusTooManyRequests, jsonRPCLimit(parsedRequest.ID)
		} //else if added {
		// gotils.L(ctx).Debug().Printf("Added new visitor, ip: %v", parsedRequest.RemoteAddr)
		// }

		if !t.MatchAnyRule(parsedRequest.Path) {
			// gotils.L(ctx).Debug().Print("Request blocked: Method not allowed")
			return http.StatusMethodNotAllowed, jsonRPCUnauthorized(parsedRequest.ID, parsedRequest.Path)
		}
		if t.blockRangeLimit > 0 && parsedRequest.Path == "eth_getLogs" {
			r, invalid, err := t.parseRange(ctx, parsedRequest)
			if err != nil {
				return http.StatusInternalServerError, jsonRPCError(parsedRequest.ID, jsonRPCInternal, err.Error())
			} else if invalid != nil {
				gotils.L(ctx).Info().Printf("Request blocked: Invalid params: %v", invalid)
				return http.StatusBadRequest, jsonRPCError(parsedRequest.ID, jsonRPCInvalidParams, invalid.Error())
			}
			if r != nil {
				if l := r.len(); l > t.blockRangeLimit {
					gotils.L(ctx).Info().Println("Request blocked: Exceeds block range limit, range:", l, "limit:", t.blockRangeLimit)
					return http.StatusBadRequest, jsonRPCBlockRangeLimit(parsedRequest.ID, l, t.blockRangeLimit)
				}
				if union == nil {
					union = r
				} else {
					union.extend(r)
					if l := union.len(); l > t.blockRangeLimit {
						gotils.L(ctx).Info().Println("Request blocked: Exceeds block range limit, range:", l, "limit:", t.blockRangeLimit)
						return http.StatusBadRequest, jsonRPCBlockRangeLimit(parsedRequest.ID, l, t.blockRangeLimit)
					}
				}
			}
		}
	}
	return 0, nil
}

type blockRange struct{ start, end uint64 }

func (b blockRange) len() uint64 {
	return b.end - b.start + 1
}

func (b *blockRange) extend(b2 *blockRange) {
	if b2.start < b.start {
		b.start = b2.start
	}
	if b2.end > b.end {
		b.end = b2.end
	}
}

// parseRange returns a block range if one exists, or an error if the request is invalid.
func (t *myTransport) parseRange(ctx context.Context, request ModifiedRequest) (r *blockRange, invalid, internal error) {
	if len(request.Params) == 0 {
		return nil, nil, nil
	}
	type filterQuery struct {
		BlockHash *string          `json:"blockHash"`
		FromBlock *rpc.BlockNumber `json:"fromBlock"`
		ToBlock   *rpc.BlockNumber `json:"toBlock"`
	}
	var fq filterQuery
	err := json.Unmarshal(request.Params[0], &fq)
	if err != nil {
		return nil, err, nil
	}
	if fq.BlockHash != nil {
		return nil, nil, nil
	}
	var start, end uint64
	if fq.FromBlock != nil {
		switch *fq.FromBlock {
		case rpc.LatestBlockNumber, rpc.PendingBlockNumber:
			l, err := t.latestBlock.get(ctx)
			if err != nil {
				return nil, nil, err
			}
			start = l
		default:
			start = uint64(*fq.FromBlock)
		}
	}
	if fq.ToBlock == nil {
		l, err := t.latestBlock.get(ctx)
		if err != nil {
			return nil, nil, err
		}
		end = l
	} else {
		switch *fq.ToBlock {
		case rpc.LatestBlockNumber, rpc.PendingBlockNumber:
			l, err := t.latestBlock.get(ctx)
			if err != nil {
				return nil, nil, err
			}
			end = l
		default:
			end = uint64(*fq.ToBlock)
		}
	}

	return &blockRange{start: start, end: end}, nil, nil
}

type latestBlock struct {
	url    string
	client *goclient.Client

	mu sync.RWMutex // Protects everything below.

	next chan struct{} // Set when an update is running, and closed when the next result is available.

	num uint64
	err error
	at  *time.Time // When num and err were set.
}

func (l *latestBlock) get(ctx context.Context) (uint64, error) {
	l.mu.RLock()
	next, num, err, at := l.next, l.num, l.err, l.at
	l.mu.RUnlock()
	if at != nil && time.Since(*at) < 5*time.Second {
		return num, err
	}
	if next == nil {
		// No update in progress, so try to trigger one.
		next, num, err = l.update()
	}
	if next != nil {
		// Wait on update to complete.
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-next:
		}
		l.mu.RLock()
		num = l.num
		err = l.err
		l.mu.RUnlock()
	}

	return num, err

}

// update updates (num, err, at). Only one instance may run at a time, and it
// spot is reserved by setting next, which is closed when the operation completes.
// Returns a chan to wait on if another instance is already running. Otherwise
// returns num and err if the operation is complete.
func (l *latestBlock) update() (chan struct{}, uint64, error) {
	l.mu.Lock()
	if next := l.next; next != nil {
		// Someone beat us to it, return their next chan.
		l.mu.Unlock()
		return next, 0, nil
	}
	next := make(chan struct{})
	l.next = next
	l.mu.Unlock()

	var latest uint64
	var err error
	if l.client == nil {
		l.client, err = goclient.Dial(l.url)
	}
	if err == nil {
		var lBig *big.Int
		lBig, err = l.client.LatestBlockNumber(context.Background())
		if err == nil {
			latest = lBig.Uint64()
		}
	}
	now := time.Now()

	l.mu.Lock()
	l.num = latest
	l.err = err
	l.at = &now
	l.next = nil
	l.mu.Unlock()

	close(next)

	return nil, latest, err
}
