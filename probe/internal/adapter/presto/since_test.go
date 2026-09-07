// oracle-carrier: probe/internal/adapter/presto/since_test.go
package presto

type SinceInput struct {
	Value string
}

type SinceOutcome struct {
	Accepted bool
}

var oracleRows = []struct {
	FP   string
	Case string
	In   any
	Want any
}{
	{FP: "FP-AD-9", Case: "seconds-one-below-9223372035s-accepted", In: SinceInput{Value: "9223372035s"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "seconds-max-safe-9223372036s->=MaxInt64/unit-accepted", In: SinceInput{Value: "9223372036s"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "seconds-first-overflow-9223372037s-exit_code=1-no-/v1/query-rejected", In: SinceInput{Value: "9223372037s"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "minutes-one-below-153722866m-accepted", In: SinceInput{Value: "153722866m"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "minutes-max-safe-153722867m-accepted", In: SinceInput{Value: "153722867m"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "minutes-first-overflow-153722868m-exit_code=1-no-/v1/query-rejected", In: SinceInput{Value: "153722868m"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "hours-one-below-2562046h-accepted", In: SinceInput{Value: "2562046h"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "hours-max-safe-2562047h-accepted", In: SinceInput{Value: "2562047h"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "hours-first-overflow-2562048h-exit_code=1-no-/v1/query-rejected", In: SinceInput{Value: "2562048h"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "days-one-below-106750d-accepted", In: SinceInput{Value: "106750d"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "days-max-safe-106751d-accepted", In: SinceInput{Value: "106751d"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "days-first-overflow-106752d-exit_code=1-no-/v1/query-rejected", In: SinceInput{Value: "106752d"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "observed-overflow-200000d-exit_code=1-no-/v1/query-rejected", In: SinceInput{Value: "200000d"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "positive-wrap-213504d-exit_code=1-no-/v1/query-duration<0-rejected", In: SinceInput{Value: "213504d"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "largest-parsed-integer-9223372036854775807s-ParseInt-rejected", In: SinceInput{Value: "9223372036854775807s"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "integer-overflow-int64-9223372036854775808d-ParseInt-rejected", In: SinceInput{Value: "9223372036854775808d"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-9", Case: "zero-identity-0s-accepted", In: SinceInput{Value: "0s"}, Want: SinceOutcome{Accepted: true}},
	{FP: "FP-AD-9", Case: "schema-precedence-1x-ValidateParams-rejected", In: SinceInput{Value: "1x"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-3", Case: "lexical-invalid-decorator_list=[]", In: SinceInput{Value: "[]"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-3", Case: "lexical-invalid-cfile=tmp_path/\"yaml\"/\"__init__.pyc\"", In: SinceInput{Value: "tmp_path/yaml/__init__.pyc"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-3", Case: "lexical-invalid-PYTHONPATH=/tmp/b11-hook", In: SinceInput{Value: "/tmp/b11-hook"}, Want: SinceOutcome{Accepted: false}},
	{FP: "FP-AD-3", Case: "lexical-invalid-fixture=pytest.hookimpl", In: SinceInput{Value: "pytest.hookimpl"}, Want: SinceOutcome{Accepted: false}},
}
