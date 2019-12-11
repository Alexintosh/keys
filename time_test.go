package keys

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimeInMillis(t *testing.T) {
	t1 := time.Now()
	ts := TimeToMillis(t1)
	t2 := TimeFromMillis(ts)
	assert.Equal(t, t1.Format(time.StampMilli), t2.Format(time.StampMilli))

	assert.Equal(t, TimeMs(0), TimeToMillis(time.Time{}))
	assert.Equal(t, time.Time{}, TimeFromMillis(0))
}

func TestRFC3339Milli(t *testing.T) {
	t1 := TimeFromMillis(1234567890010)
	s1 := t1.Format(RFC3339Milli)
	require.Equal(t, "2009-02-13T15:31:30.010-08:00", s1)
	tout, err := time.Parse(RFC3339Milli, s1)
	require.NoError(t, err)
	require.Equal(t, t1, tout)
	require.Equal(t, TimeToMillis(t1), TimeToMillis(tout))
}

func parseTime(t *testing.T, s string) time.Time {
	ti, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return ti
}

func TestTimeUntilNext(t *testing.T) {
	t1 := timeUntilNext(parseTime(t, "2018-11-12T11:49:00Z"), time.Hour)
	assert.Equal(t, time.Minute*41, t1)

	t2 := timeUntilNext(parseTime(t, "2018-11-12T11:01:00Z"), time.Hour)
	assert.Equal(t, time.Minute*29, t2)
}

func TestPreviousTime(t *testing.T) {
	prev := previousTime(parseTime(t, "2018-11-12T11:59:59.999Z"), time.Hour)
	assert.Equal(t, "2018-11-12T11:00:00Z", prev.Format(time.RFC3339))

	prev2 := previousTime(parseTime(t, "2018-11-12T11:29:59.999Z"), time.Hour)
	assert.Equal(t, "2018-11-12T10:00:00Z", prev2.Format(time.RFC3339))
}

func TestNextTime(t *testing.T) {
	curr := nextTime(parseTime(t, "2018-11-12T11:59:59.999Z"), time.Hour)
	assert.Equal(t, "2018-11-12T12:00:00Z", curr.Format(time.RFC3339))

	curr2 := nextTime(parseTime(t, "2018-11-12T11:29:59.999Z"), time.Hour)
	assert.Equal(t, "2018-11-12T11:00:00Z", curr2.Format(time.RFC3339))
}

func TestFormatWithPrecision(t *testing.T) {
	ti := parseTime(t, "2018-11-12T10:59:03.999Z")
	assert.Equal(t, "20181112105903", formatWithPrecision(ti, time.Second))
	assert.Equal(t, "201811121059", formatWithPrecision(ti, time.Minute))
	assert.Equal(t, "201811121055", formatWithPrecision(ti, time.Minute*5))
	assert.Equal(t, "2018111210", formatWithPrecision(ti, time.Hour))
}