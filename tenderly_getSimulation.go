package main

type TenderlySimulation struct {
	Contracts  []interface{} `json:"contracts"`
	Simulation struct {
		AccessList  interface{} `json:"access_list"`
		Alias       string      `json:"alias"`
		BlockHash   string      `json:"block_hash"`
		BlockHeader struct {
			BaseFeePerGas    string      `json:"baseFeePerGas"`
			Difficulty       string      `json:"difficulty"`
			ExtraData        string      `json:"extraData"`
			GasLimit         string      `json:"gasLimit"`
			GasUsed          string      `json:"gasUsed"`
			Hash             string      `json:"hash"`
			LogsBloom        string      `json:"logsBloom"`
			Miner            string      `json:"miner"`
			MixHash          string      `json:"mixHash"`
			Nonce            string      `json:"nonce"`
			Number           string      `json:"number"`
			ParentHash       string      `json:"parentHash"`
			ReceiptsRoot     string      `json:"receiptsRoot"`
			Sha3Uncles       string      `json:"sha3Uncles"`
			Size             string      `json:"size"`
			StateRoot        string      `json:"stateRoot"`
			Timestamp        string      `json:"timestamp"`
			TotalDifficulty  string      `json:"totalDifficulty"`
			TransactionsRoot string      `json:"transactionsRoot"`
			Uncles           interface{} `json:"uncles"`
		} `json:"block_header"`
		BlockNumber int64  `json:"block_number"`
		BranchRoot  bool   `json:"branch_root"`
		CreatedAt   string `json:"created_at"`
		ForkHeight  int64  `json:"fork_height"`
		ForkID      string `json:"fork_id"`
		From        string `json:"from"`
		Gas         int64  `json:"gas"`
		GasPrice    string `json:"gas_price"`
		Hash        string `json:"hash"`
		ID          string `json:"id"`
		Input       string `json:"input"`
		Internal    bool   `json:"internal"`
		NetworkID   string `json:"network_id"`
		Nonce       int64  `json:"nonce"`
		ParentID    string `json:"parent_id"`
		ProjectID   string `json:"project_id"`
		QueueOrigin string `json:"queue_origin"`
		Receipt     struct {
			BlockHash         string      `json:"blockHash"`
			BlockNumber       string      `json:"blockNumber"`
			ContractAddress   interface{} `json:"contractAddress"`
			CumulativeGasUsed string      `json:"cumulativeGasUsed"`
			EffectiveGasPrice string      `json:"effectiveGasPrice"`
			From              string      `json:"from"`
			GasUsed           string      `json:"gasUsed"`
			Logs              []struct {
				Address          string   `json:"address"`
				BlockHash        string   `json:"blockHash"`
				BlockNumber      string   `json:"blockNumber"`
				Data             string   `json:"data"`
				LogIndex         string   `json:"logIndex"`
				Removed          bool     `json:"removed"`
				Topics           []string `json:"topics"`
				TransactionHash  string   `json:"transactionHash"`
				TransactionIndex string   `json:"transactionIndex"`
			} `json:"logs"`
			LogsBloom        string `json:"logsBloom"`
			Status           string `json:"status"`
			To               string `json:"to"`
			TransactionHash  string `json:"transactionHash"`
			TransactionIndex string `json:"transactionIndex"`
			Type             string `json:"type"`
		} `json:"receipt"`
		StateObjects []struct {
			Address string `json:"address"`
			Data    struct {
				Balance string `json:"balance"`
				Nonce   int64  `json:"nonce"`
			} `json:"data"`
		} `json:"state_objects"`
		Status           bool   `json:"status"`
		Timestamp        string `json:"timestamp"`
		To               string `json:"to"`
		TransactionIndex int64  `json:"transaction_index"`
		Value            string `json:"value"`
	} `json:"simulation"`
	Transaction struct {
		AccessList        interface{} `json:"access_list"`
		Addresses         []string    `json:"addresses"`
		BlockHash         string      `json:"block_hash"`
		BlockNumber       int64       `json:"block_number"`
		CallTrace         interface{} `json:"call_trace"`
		ContractIds       []string    `json:"contract_ids"`
		CumulativeGasUsed int64       `json:"cumulative_gas_used"`
		DecodedInput      interface{} `json:"decoded_input"`
		EffectiveGasPrice int64       `json:"effective_gas_price"`
		From              string      `json:"from"`
		FunctionSelector  string      `json:"function_selector"`
		Gas               int64       `json:"gas"`
		GasFeeCap         int64       `json:"gas_fee_cap"`
		GasPrice          int64       `json:"gas_price"`
		GasTipCap         int64       `json:"gas_tip_cap"`
		GasUsed           int64       `json:"gas_used"`
		Hash              string      `json:"hash"`
		Index             int64       `json:"index"`
		Input             string      `json:"input"`
		Method            string      `json:"method"`
		NetworkID         string      `json:"network_id"`
		Nonce             int64       `json:"nonce"`
		Status            bool        `json:"status"`
		Timestamp         string      `json:"timestamp"`
		To                string      `json:"to"`
		TransactionInfo   struct {
			BalanceDiff []struct {
				Address  string `json:"address"`
				Dirty    string `json:"dirty"`
				IsMiner  bool   `json:"is_miner"`
				Original string `json:"original"`
			} `json:"balance_diff"`
			BlockNumber int64 `json:"block_number"`
			CallTrace   struct {
				AbsolutePosition int64 `json:"absolute_position"`
				BalanceDiff      []struct {
					Address  string `json:"address"`
					Dirty    string `json:"dirty"`
					IsMiner  bool   `json:"is_miner"`
					Original string `json:"original"`
				} `json:"balance_diff"`
				BlockTimestamp string      `json:"block_timestamp"`
				CallType       string      `json:"call_type"`
				CallerOp       string      `json:"caller_op"`
				CallerPc       int64       `json:"caller_pc"`
				Calls          interface{} `json:"calls"`
				ContractName   string      `json:"contract_name"`
				DecodedOutput  interface{} `json:"decoded_output"`
				From           string      `json:"from"`
				FromBalance    string      `json:"from_balance"`
				FunctionOp     string      `json:"function_op"`
				FunctionPc     int64       `json:"function_pc"`
				Gas            int64       `json:"gas"`
				GasUsed        int64       `json:"gas_used"`
				Hash           string      `json:"hash"`
				Input          string      `json:"input"`
				IntrinsicGas   int64       `json:"intrinsic_gas"`
				Logs           []struct {
					Anonymous bool        `json:"anonymous"`
					Inputs    interface{} `json:"inputs"`
					Name      string      `json:"name"`
					Raw       struct {
						Address string   `json:"address"`
						Data    string   `json:"data"`
						Topics  []string `json:"topics"`
					} `json:"raw"`
				} `json:"logs"`
				NetworkID string `json:"network_id"`
				NonceDiff []struct {
					Address  string `json:"address"`
					Dirty    string `json:"dirty"`
					Original string `json:"original"`
				} `json:"nonce_diff"`
				Output    string `json:"output"`
				RefundGas int64  `json:"refund_gas"`
				StateDiff []struct {
					Dirty    interface{} `json:"dirty"`
					Original interface{} `json:"original"`
					Raw      []struct {
						Address  string `json:"address"`
						Dirty    string `json:"dirty"`
						Key      string `json:"key"`
						Original string `json:"original"`
					} `json:"raw"`
					Soltype interface{} `json:"soltype"`
				} `json:"state_diff"`
				To        string `json:"to"`
				ToBalance string `json:"to_balance"`
				Value     string `json:"value"`
			} `json:"call_trace"`
			ConsoleLogs     interface{} `json:"console_logs"`
			ContractAddress string      `json:"contract_address"`
			ContractID      string      `json:"contract_id"`
			CreatedAt       string      `json:"created_at"`
			IntrinsicGas    int64       `json:"intrinsic_gas"`
			Logs            []struct {
				Anonymous bool        `json:"anonymous"`
				Inputs    interface{} `json:"inputs"`
				Name      string      `json:"name"`
				Raw       struct {
					Address string   `json:"address"`
					Data    string   `json:"data"`
					Topics  []string `json:"topics"`
				} `json:"raw"`
			} `json:"logs"`
			Method    interface{} `json:"method"`
			NonceDiff []struct {
				Address  string `json:"address"`
				Dirty    string `json:"dirty"`
				Original string `json:"original"`
			} `json:"nonce_diff"`
			Parameters   interface{} `json:"parameters"`
			RawStateDiff interface{} `json:"raw_state_diff"`
			RefundGas    int64       `json:"refund_gas"`
			StackTrace   interface{} `json:"stack_trace"`
			StateDiff    []struct {
				Dirty    interface{} `json:"dirty"`
				Original interface{} `json:"original"`
				Raw      []struct {
					Address  string `json:"address"`
					Dirty    string `json:"dirty"`
					Key      string `json:"key"`
					Original string `json:"original"`
				} `json:"raw"`
				Soltype interface{} `json:"soltype"`
			} `json:"state_diff"`
			TransactionID string `json:"transaction_id"`
		} `json:"transaction_info"`
		Value string `json:"value"`
	} `json:"transaction"`
}
