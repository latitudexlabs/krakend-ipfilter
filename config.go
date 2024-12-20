package ipfilter

import (
	"encoding/json"
	"fmt"

	"github.com/luraproject/lura/v2/config"
)

// Config is config of ipfilter
type Config struct {
	Deny  []string
	Allow []string
}

// Namespace is ipfilter's config key in extra config
const Namespace = "github_com/anshulgoel27/krakend-ipfilter"

func ConfigGetter(e config.ExtraConfig) *Config {
	v, ok := e[Namespace].(map[string]interface{})
	if !ok {
		return nil
	}

	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal krakend-ipfilter config error: %s", err.Error()))
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		panic(fmt.Sprintf("unmarshal krakend-ipfilter config error: %s", err.Error()))
	}

	return &cfg
}
