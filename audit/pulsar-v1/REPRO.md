# Reproduce

```
cd ~/work/lux/luxfi/pulsar
go build ./ref/go/pkg/pulsar/
go test  ./ref/go/pkg/pulsar/ -run 'ThresholdV03|NoHintSecret|NonceCert|NonceTranscript|FindHint|Boundary|BCCParam|Partial|CanonicalNonce|AbortClasses|TreeAggregate|MergeAggregates|NoT0|ProductionBCC|PublishingFullW' -count=1
go vet  ./ref/go/pkg/pulsar/
```

Spec: `spec/threshold-mldsa-boundary-clearance.tex` (latexmk -pdf).
Blockers: `BLOCKERS.md` (PULSAR-V13-HINT-LEAK / W-LEAK / PARTIAL-Z-PROOF + criteria).
