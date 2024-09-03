package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"strconv"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	fileUtil "github.com/projectdiscovery/utils/file"
	sliceUtil "github.com/projectdiscovery/utils/slice"
)

type Options struct {
	list               string
	parameters         string
	chunk              int
	values             goflags.StringSlice
	generationStrategy goflags.StringSlice
	valueStrategy      string
	output             string
	doubleEncode       bool
}

var options *Options

func main() {
	options = ParseOptions()
	params := getParams()

	var input io.Reader
	if options.list != "" {
		f, err := os.Open(options.list)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		defer f.Close()
		input = f
	} else {
		input = os.Stdin
	}

	hasNormalStrat := sliceUtil.Contains(options.generationStrategy, "normal")
	hasCombineStrat := sliceUtil.Contains(options.generationStrategy, "combine")
	hasIgnoreStrat := sliceUtil.Contains(options.generationStrategy, "ignore")

	scn := bufio.NewScanner(input)
	for scn.Scan() {
		u, err := url.Parse(scn.Text())

		if err != nil {
			gologger.Error().Str("url", u.String()).Str("parseError", err.Error()).Msg(fmt.Errorf("invalid url: skipping url", err).Error())
			continue
		}

		if hasNormalStrat {
			newParamsOnlyStrat(u, params)
		}

		if hasCombineStrat {
			combineStrat(u)
		}

		if hasIgnoreStrat {
			ignoreStrat(u, params)
		}
	}
}

func ParseOptions() *Options {
	options := &Options{}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	flags := goflags.NewFlagSet()
	flags.SetDescription("A tool designed for URL modification with specific modes to manipulate parameters and their values")

	flags.StringVarP(&options.list, "list", "l", "", "List of URLS to edit (stdin could be used alternatively)")
	flags.StringVarP(&options.parameters, "parameters", "p", "", "Parameter wordlist")
	flags.IntVarP(&options.chunk, "chunk", "c", 15, "Number of parameters in each URL")
	flags.StringSliceVarP(&options.values, "value", "v", nil, "Value for the parameters", goflags.StringSliceOptions)

	generationStrategyHelp := `
	Select the mode strategy from the available choices:
					normal:  Remove all parameters and put the wordlist
					combine: Pitchfork combine on the existing parameters
					ignore:  Don't touch the URL and append the parameters to the URL
				`
	flags.StringSliceVarP(&options.generationStrategy, "generate-strategy", "gs", nil, generationStrategyHelp, goflags.CommaSeparatedStringSliceOptions)

	valueStrategyHelp := `Select the strategy from the available choices:
					replace: Replace the current URL values with the given values
					suffix:  Append the value to the end of the parameters
				`
	flags.StringVarP(&options.valueStrategy, "value-strategy", "vs", "suffix", valueStrategyHelp)

	flags.BoolVarP(&options.doubleEncode, "double-encode", "de", false, "Double encode the values")

	if err := flags.Parse(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	if err := options.validateOptions(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	return options
}

func (options *Options) validateOptions() error {
	// check if no urls were given
	if !fileUtil.HasStdin() && options.list == "" {
		return fmt.Errorf("No URLs were given")
	}

	// check if output file already exists
	if fileUtil.FileExists(options.output) && options.output != "" {
		return fmt.Errorf("Output file already exists")
	}

	// check if url file does not exist
	if !fileUtil.FileExists(options.list) && options.list != "" {
		return fmt.Errorf("URL list does not exist")
	}

	// check if no parameter file is given (ignore this for combine mode)
	if options.parameters == "" && !(len(options.generationStrategy) == 1 && sliceUtil.Contains(options.generationStrategy, "combine")) {
		return fmt.Errorf("Parameter wordlist file is not given")
	}

	// check if parameter file does not exist
	if !fileUtil.FileExists(options.parameters) && options.parameters != "" {
		return fmt.Errorf("Parameter wordlist file does not exist")
	}

	// check if value strategy is not valid
	if options.valueStrategy != "replace" && options.valueStrategy != "suffix" {
		return fmt.Errorf("Value strategy is not valid")
	}

	// check if generation strategy is valid
	if !sliceUtil.Contains(options.generationStrategy, "combine") &&
		!sliceUtil.Contains(options.generationStrategy, "ignore") &&
		!sliceUtil.Contains(options.generationStrategy, "normal") {
		return fmt.Errorf("Generation strategy is not valid")
	}

	// check if no value is given
	if options.values == nil {
		return fmt.Errorf("No values are given")
	}

	return nil
}

func getParams() []string {
	params := []string{}

	if len(options.generationStrategy) == 1 && sliceUtil.Contains(options.generationStrategy, "combine") {
		return params
	}

	f, err := os.Open(options.parameters)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer f.Close()

	scn := bufio.NewScanner(f)
	for scn.Scan() {
		params = append(params, scn.Text())
	}

	return params
}

func combineStrat(u *url.URL) {
	// parse each url
	queryParams := u.Query()
	numOfOldParams := len(queryParams)

	urlKeys := make([]string, len(queryParams))
	i := 0
	for key := range queryParams {
		urlKeys[i] = key
		i++
	}

	value := "soheil"
	// double encode the value if the flag is set
	if options.doubleEncode {
		value = url.QueryEscape(value)
	}

	urlCopy := *u
	// each iteration contains a url with the number of parameters provided by the chunk size flag
	for iteration := 0; iteration < numOfOldParams; iteration++ {
		query := u.Query()

		// modify one parameter in each iteration
		if options.valueStrategy == "replace" {
			query.Set(urlKeys[iteration], value)
		} else {
			query.Set(urlKeys[iteration], query.Get(urlKeys[iteration])+value)
		}

		urlCopy.RawQuery = query.Encode()
		fmt.Println(urlCopy.String())
	}
}

func ignoreStrat(u *url.URL, params []string) {
	// parse each url
	queryParams := u.Query()

	// number of iteration is equivalent to the number of URLs being generated for each value
	numOfOldParams := len(queryParams)
	ignoreChunk := options.chunk - numOfOldParams
	if ignoreChunk <= 0 {
		gologger.Error().Str("URL", u.String()).Str("paramsCount", strconv.Itoa(numOfOldParams)).Str("chunk", strconv.Itoa(options.chunk)).Msg("chunk value must be greater than url query params count, ignoring url")
		return
	}

	numOfIterations := int(math.Ceil(float64(len(params)) / float64(ignoreChunk)))

	value := "soheil"

	// double encode the value if the flag is set
	if options.doubleEncode {
		value = url.QueryEscape(value)
	}

	urlCopy := *u
	// each iteration contains a url with the number of parameters provided by the chunk size flag
	for iteration := 0; iteration < numOfIterations; iteration++ {
		iterationParams := params[iteration*ignoreChunk : intMin((iteration+1)*ignoreChunk, len(params))]
		query := u.Query()

		for _, param := range iterationParams {
			if !query.Has(param) {
				query.Set(param, value)
			}
		}

		urlCopy.RawQuery = query.Encode()
		fmt.Println(urlCopy.String())
	}
}

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func newParamsOnlyStrat(u *url.URL, params []string) {
	numOfIterations := int(math.Ceil(float64(len(params)) / float64(options.chunk)))

	// get the base url (without the params and values)
	baseUrl := u.Scheme + "://" + u.Host + u.Path

	// parse the base url
	parsedUrl, err := url.Parse(baseUrl)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	// each iteration contains a url with the number of parameters provided by the chunk size flag
	for iteration := 0; iteration < numOfIterations; iteration++ {
		iterationParams := params[iteration*options.chunk : intMin((iteration+1)*options.chunk, len(params))]
		iterationQueryParams := url.Values{}

		// set new parameters with the given values
		for _, param := range iterationParams {
			iterationQueryParams.Add(param, "soheil")
		}

		// add parameters to a copy of the base url
		parsedUrl.RawQuery = iterationQueryParams.Encode()
		fmt.Println(parsedUrl)
	}
}
