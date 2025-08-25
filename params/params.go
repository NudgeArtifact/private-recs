package params

import (
	"fmt"
	"strconv"
	"encoding/json"
	"private-recs/utils"
)

type PowerItParams struct {
        K             int   // number of components to build/rank of the approximation
        N_iters       int   // number of iterations for power-iteration
        N_decimals    int   // number of fractional digits of precision
        Norm_decimals int   // number of fractional digits of precision for norm (in Newton iteration)
	Newton_iters int

        Normalize     bool  // whether to normalize the matrix
        Verbose       bool  // whether to print details during execution
        Start_random  bool
        Save_truncate bool
}

func SetPowerItParams(k, n_iters, n_decimals, norm_decimals, newton_iters int, start_random, save_trunc bool) *PowerItParams {
        params := new(PowerItParams)

        params.K = k
        params.N_iters = n_iters
        params.N_decimals = n_decimals
        params.Norm_decimals = norm_decimals
	params.Newton_iters = newton_iters

        params.Normalize = false
        params.Verbose = false
        params.Start_random = start_random
        params.Save_truncate = save_trunc

        return params
}

func (params *PowerItParams) ToString() string {
        out := "powerIt_k="
        out += strconv.Itoa(params.K)
        out += "_"
        out += strconv.Itoa(params.N_iters)
        out += "iters_"
        out += strconv.Itoa(params.N_decimals)
        out += "digits_"
        out += strconv.Itoa(params.Norm_decimals)
        out += "normDigits_"
        out += strconv.Itoa(params.Newton_iters)
	out += "newton"

        if params.Start_random {
                out += "_randinit"
        }

        if params.Save_truncate {
                out += "_saveTrunc"
        }

        return out
}

func FromJSON(path string) *PowerItParams {
	f := utils.OpenFile(path)
	defer f.Close()

	var p PowerItParams
	if err := json.NewDecoder(f).Decode(&p); err != nil {
		fmt.Println(err)
		panic("Error reading PowerItParams from JSON")
		return nil
	}

	return &p
}
