#!/usr/bin/env nextflow

process IRIDA_LINKER {

    container 'python:3.10'

    conda 'conda-forge::python=3.10'

    input:
    tuple val(project_id), val(email)
    
    output:
    path "*_samples.csv", emit: csv
    
    script:
    """
    iridaLinker.py \
        --project ${project_id} \
        --email ${email} \
        --output .
    """
}

workflow {
    IRIDA_LINKER(ch_input)
} 