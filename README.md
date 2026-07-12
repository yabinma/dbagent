# dbagent

## Generated code

`gen/go`, `gen/python`, `libs/py/rca_common/rca_common/schemas/generated`,
and `web/src/types/generated` are gitignored -- never committed. Before
your first local build/test, regenerate them from source:

```
scripts/gen-proto.sh            # gen/go, gen/python (from proto/*.proto)
schemas/generate-pydantic.sh    # rca_common schemas/generated (from schemas/*.schema.json)
cd schemas && npm ci && node generate-ts.js   # web/src/types/generated
```

CI regenerates these fresh in every job that needs them; see the
"Generated-code policy" note at the top of `.github/workflows/ci.yml`.