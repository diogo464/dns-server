package dns

import "testing"

func assert[T comparable](t *testing.T, lhs, rhs T, msg ...string) {
	if lhs != rhs {
		t.Fatalf("%v\n\t%v != %v\n", msg, lhs, rhs)
	}
}

func TestSplitNameIntoLabels(t *testing.T) {
	s := splitNameIntoLabels("google.com")
	assert(t, s[0], "google")
	assert(t, s[1], "com")
	assert(t, len(s), 2)

	s = splitNameIntoLabels("google.com.")
	assert(t, s[0], "google")
	assert(t, s[1], "com")
	assert(t, len(s), 2)

	s = splitNameIntoLabels("mail.google.com.")
	assert(t, s[0], "mail")
	assert(t, s[1], "google")
	assert(t, s[2], "com")
	assert(t, len(s), 3)
}
