package switches

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

type TPLINKSwitchClient interface {
	GetPortStats() ([]portStats, error)
	GetHost() string
	// Login()
}

const (
	statePortOff = iota
	statePortOn
)

//nolint:deadcode,varcheck // "Link Down","Auto","10Half","10Full","100Half","100Full","1000Full","")
const (
	linkStateDown = iota
	linkStateAuto
	linkState10Half
	linkState10Full
	linkState100Half
	linkState100Full
	linkState1000Full
)

type PortStats struct {
	// 1-up / 2-down / 3-testing
	AdminStatus float64

	// 1-up / 2-down / 3-testing
	OperStatus float64

	Speed float64

	InUcastPkts  float64
	InErrors     float64
	OutUcastPkts float64
	OutErrors    float64
}

type TPLINKSwitch struct {
	log        zerolog.Logger
	httpClient *httpClient

	host     string
	username string
	password string
}

type portStats struct {
	State      int
	LinkStatus int
	PktCount   map[string]int
}

type httpClient struct {
	*http.Client

	inFlightGauge prometheus.Gauge
	counter       *prometheus.CounterVec
	histVec       *prometheus.HistogramVec
}

func newHTTPClient() *httpClient {
	c := &httpClient{
		Client: &http.Client{},
		inFlightGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "switch_in_flight_requests",
			Help: "A gauge of in-flight requests for the wrapped client.",
		}),
		counter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "switch_requests_total",
				Help: "A counter for requests from the wrapped client.",
			},
			[]string{"code", "method"},
		),
		histVec: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "switch_request_duration_seconds",
				Help:    "A histogram of request latencies.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
	}

	c.Transport = promhttp.InstrumentRoundTripperInFlight(c.inFlightGauge,
		promhttp.InstrumentRoundTripperCounter(c.counter,
			promhttp.InstrumentRoundTripperDuration(c.histVec, http.DefaultTransport),
		),
	)

	return c
}

func (client *TPLINKSwitch) GetHost() string {
	return client.host
}

const rePatternArray = `\[[^]]*\]`

var rePortStatus = regexp.MustCompile(`(?s)<script>` +
	`(.*max_port_num\s+=\s+(\d);.*` +
	`state:(` + rePatternArray + `),.*` +
	`link_status:(` + rePatternArray + `),.*` +
	`pkts:(` + rePatternArray + `).*` +
	`)</script>`)

func (c *TPLINKSwitch) parsePortStatus(data []byte) ([]PortStats, error) {
	if bytes.Contains(data, []byte(`logonInfo = new Array`)) {
		return nil, fmt.Errorf("authentication was not successful")
	}

	matches := rePortStatus.FindSubmatch(data)
	if len(matches) == 0 {
		c.log.Error().Msg(string(data))
		return nil, fmt.Errorf("regular expression for port statistics did not match")
	}

	var maxPortNum int
	if err := json.Unmarshal(matches[2], &maxPortNum); err != nil {
		return nil, fmt.Errorf("unable to read max_port_num `%s`", string(matches[2]))
	}

	var state []int64
	if err := json.Unmarshal(matches[3], &state); err != nil {
		return nil, fmt.Errorf("unable to read state `%s`", string(matches[3]))
	}

	var linkStatus []int64
	if err := json.Unmarshal(matches[4], &linkStatus); err != nil {
		return nil, fmt.Errorf("unable to read link_status `%s`", string(matches[4]))
	}

	var pkts []int
	if err := json.Unmarshal(matches[5], &pkts); err != nil {
		return nil, fmt.Errorf("unable to read pkts `%s`", string(matches[4]))
	}

	portStats := make([]PortStats, maxPortNum)
	for pos := range portStats {
		s := &portStats[pos]

		if v := state[pos]; v == statePortOff {
			s.AdminStatus = 2
		} else if v == statePortOn {
			s.AdminStatus = 1
		}

		switch v := linkStatus[pos]; v {
		case linkState10Full, linkState10Half:
			s.OperStatus = 1
			s.Speed = 1e7
		case linkState100Full, linkState100Half:
			s.OperStatus = 1
			s.Speed = 1e8
		case linkState1000Full:
			s.OperStatus = 1
			s.Speed = 1e9
		default:
			s.OperStatus = 2
			s.Speed = 0
		}

		s.InUcastPkts = float64(pkts[pos*4+2])
		s.InErrors = float64(pkts[pos*4+3])
		s.OutUcastPkts = float64(pkts[pos*4+0])
		s.OutErrors = float64(pkts[pos*4+1])

	}

	return portStats, nil
	//return nil, nil
}

func (s *TPLINKSwitch) GetPortStats() ([]PortStats, error) {
	// ensure we are logged in
	respLogin, err := s.httpClient.PostForm(fmt.Sprintf("http://%s/logon.cgi", s.host), url.Values{"username": {s.username}, "password": {s.password}, "logon": {"Login"}})
	if err != nil {
		return nil, err
	}
	defer respLogin.Body.Close()

	// ensure all is read
	_, err = ioutil.ReadAll(respLogin.Body)
	if err != nil {
		return nil, err
	}
	if respLogin.StatusCode/100 != 2 {
		return nil, fmt.Errorf("unexpected status code %d after login", respLogin.StatusCode)
	}

	respStats, err := s.httpClient.Get(fmt.Sprintf("http://%s/PortStatisticsRpm.htm", s.host))
	if err != nil {
		return nil, err
	}
	defer respStats.Body.Close()

	data, err := ioutil.ReadAll(respStats.Body)
	if err != nil {
		return nil, err
	}
	if respLogin.StatusCode/100 != 2 {
		return nil, fmt.Errorf("unexpected status code %d for port statistics", respLogin.StatusCode)
	}

	return s.parsePortStatus(data)
}

func (client *TPLINKSwitch) Collector() prometheus.Collector {
	return &Collector{
		client: client,

		adminStatus: prometheus.NewDesc("ifAdminStatus", "SNMP admin status", []string{"port"}, nil),
		operStatus:  prometheus.NewDesc("ifOperStatus", "SNMP operational status", []string{"port"}, nil),
		speed:       prometheus.NewDesc("ifSpeed", "SNMP interface nominal speed", []string{"port"}, nil),

		inUcastPkts:  prometheus.NewDesc("ifInUcastPkts", "SNMP received packets", []string{"port"}, nil),
		inErrors:     prometheus.NewDesc("ifInErrors", "SNMP received packets with errors", []string{"port"}, nil),
		outUcastPkts: prometheus.NewDesc("ifOutUcastPkts", "SNMP sent packets", []string{"port"}, nil),
		outErrors:    prometheus.NewDesc("ifOutErrors", "SNMP sent packets with errors", []string{"port"}, nil),
	}
}

type Collector struct {
	client *TPLINKSwitch

	adminStatus *prometheus.Desc
	operStatus  *prometheus.Desc
	speed       *prometheus.Desc

	inUcastPkts  *prometheus.Desc
	inErrors     *prometheus.Desc
	outUcastPkts *prometheus.Desc
	outErrors    *prometheus.Desc
}

// Describe implements Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.adminStatus
	ch <- c.operStatus
	ch <- c.speed
	ch <- c.inUcastPkts
	ch <- c.inErrors
	ch <- c.outUcastPkts
	ch <- c.outErrors

	c.client.httpClient.counter.Describe(ch)
	c.client.httpClient.histVec.Describe(ch)
	c.client.httpClient.inFlightGauge.Describe(ch)
}

// Collect implements Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {

	stats, err := c.client.GetPortStats()
	if err != nil {
		c.client.log.Err(err).Msg("unable to update metrics")
	}

	for pos, stat := range stats {
		portLabelValue := fmt.Sprintf("%d", pos+1)

		for _, v := range []struct {
			desc *prometheus.Desc
			val  float64
			typ  prometheus.ValueType
		}{
			{c.adminStatus, stat.AdminStatus, prometheus.GaugeValue},
			{c.operStatus, stat.OperStatus, prometheus.GaugeValue},
			{c.speed, stat.Speed, prometheus.GaugeValue},
			{c.inUcastPkts, stat.InUcastPkts, prometheus.CounterValue},
			{c.inErrors, stat.InErrors, prometheus.CounterValue},
			{c.outUcastPkts, stat.OutUcastPkts, prometheus.CounterValue},
			{c.outErrors, stat.OutErrors, prometheus.CounterValue},
		} {
			m, err := prometheus.NewConstMetric(
				v.desc,
				v.typ,
				v.val,
				portLabelValue,
			)
			if err != nil {
				c.client.log.Err(err).Msg("unable to generate metrics")
				continue
			}
			ch <- m
		}

	}

	c.client.httpClient.counter.Collect(ch)
	c.client.httpClient.histVec.Collect(ch)
	c.client.httpClient.inFlightGauge.Collect(ch)
}

func NewTPLinkSwitch(log zerolog.Logger, host string, username string, password string) *TPLINKSwitch {
	return &TPLINKSwitch{
		log:        log,
		httpClient: newHTTPClient(),
		host:       host,
		username:   username,
		password:   password,
	}
}
