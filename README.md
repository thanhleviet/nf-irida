# nf-irida

A Nextflow workflow for generating sample sheets from IRIDA projects at QIB by linking sample metadata with their corresponding files.

## Overview

This workflow connects to an IRIDA instance, retrieves sample information for specified projects, and generates CSV sample sheets containing sample names and their associated FASTQ files. It supports processing single or multiple projects and optionally merging results into a single sample sheet.

## Prerequisites
- Nextflow (>=24.04.0)
- One of the following:
  - Docker or Singularity for container execution
  - Conda for environment management
- Access to an IRIDA instance with valid credentials

## Authentication

The workflow requires IRIDA credentials for authentication. These can be provided through an environment variable. See `conf/env.config.example` for more details.

The `irida.conf` format is as follows:

```
[Settings]
client_id = UPDATE_ME
client_secret = UPDATE_ME
username = UPDATE_ME
password = UPDATE_ME
base_url = UPDATE_ME
```

## Usage
#### Single project
```bash
nextflow run -c conf/env.config \
thanhleviet/nf-irida \
    --project "123" \
    --email "admin@example.com" \
    --outdir "results" \
    -profile conda
```
#### Multiple projects

```bash
nextflow run -c conf/env.config \
thanhleviet/nf-irida \
    --project "123,456,789" \
    --email "admin@example.com" \
    --outdir "results" \
    --merge true \
    -profile conda
```

## Parameters
- `project`: The ID of the IRIDA project to link samples from.
- `email`: The email address of the user.
- `outdir`: The directory to save the output sample sheet.
- `merge`: If true, merge results into a single sample sheet.

## Contributors

- [@thanhleviet](https://github.com/thanhleviet)
