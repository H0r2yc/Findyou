package onlineengine

type OnlineengineConfig struct {
	IsIgnoreOutofChina bool
}

type onlineSearchResult struct {
	Domain  string
	Host    string
	IP      string
	Port    string
	Title   string
	Country string
	City    string
	Server  string
	Banner  string
}

type fofaQueryResult struct {
	Results      [][]string `json:"results"`
	Size         int        `json:"size"`
	Page         int        `json:"page"`
	Mode         string     `json:"mode"`
	IsError      bool       `json:"error"`
	ErrorMessage string     `json:"errmsg"`
}
