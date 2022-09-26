package main

type TenderlyFork struct {
	SimulationFork struct {
		Alias       string `json:"alias"`
		BlockNumber int64  `json:"block_number"`
		ChainConfig struct {
			BerlinBlock         int64    `json:"berlin_block"`
			ByzantiumBlock      int64    `json:"byzantium_block"`
			ChainID             int64    `json:"chain_id"`
			ConstantinopleBlock int64    `json:"constantinople_block"`
			DaoForkBlock        int64    `json:"dao_fork_block"`
			Eip150Block         int64    `json:"eip_150_Block"`
			Eip150Hash          string   `json:"eip_150_Hash"`
			Eip155Block         int64    `json:"eip_155_block"`
			Eip158Block         int64    `json:"eip_158_block"`
			Ethash              struct{} `json:"ethash"`
			HomesteadBlock      int64    `json:"homestead_block"`
			IstanbulBlock       int64    `json:"istanbul_block"`
			LondonBlock         int64    `json:"london_block"`
			MuirGlacierBlock    int64    `json:"muir_glacier_block"`
			PetersburgBlock     int64    `json:"petersburg_block"`
			Type                string   `json:"type"`
		} `json:"chain_config"`
		CreatedAt        string      `json:"created_at"`
		ForkConfig       interface{} `json:"fork_config"`
		GlobalHead       string      `json:"global_head"`
		ID               string      `json:"id"`
		NetworkID        string      `json:"network_id"`
		ProjectID        string      `json:"project_id"`
		TransactionIndex int64       `json:"transaction_index"`
	} `json:"simulation_fork"`
}
