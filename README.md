# OSCAL Lula
Experiments using [OSCAL](https://pages.nist.gov/OSCAL/) and [Lula](https://github.com/defenseunicorns/lula) for continuous compliance testing.

## Generate findings
```sh
prowler aws --compliance nist_800_53_revision_5_aws -f ca-central-1 us-east-1
```

## Add component
```sh
lula generate component \
    --catalog-source https://raw.githubusercontent.com/usnistgov/oscal-content/refs/heads/main/nist.gov/SP800-53/rev5/yaml/NIST_SP-800-53_rev5_catalog.yaml \
    --component "superset" \
    --requirements "ac-3,ac-4" \
    --output-file oscal.yaml
```

## Run validations
```sh
lula validate -f oscal-superset.yaml 
```