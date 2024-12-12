#!/usr/bin/env nextflow

process IRIDA_LINKER {
    publishDir "${params.outdir}", mode: 'copy', enabled: params.merge ? false : true

    container 'community.wave.seqera.io/library/python_requests:fcde07da6fa98799'

    conda 'conda-forge::python=3.10 conda-forge::requests'

    tag "ProjectID: ${project_id}"
    
    input:
    val(project_id)
    
    output:
    path "*_samples.csv", emit: csv
    
    script:
    """
    iridaLinker.py \
        --project ${project_id} \
        --email ${params.email} \
        --output .
    """
}

process MERGE_SAMPLE_SHEET {
    publishDir "${params.outdir}", mode: 'copy', enabled: params.merge ? true : false
    
    tag {"Merging sample sheet"}
    
    container 'community.wave.seqera.io/library/csvtk:22cb155b42ced0de'
    conda 'bioconda::csvtk=0.31.0'
    
    cpus 1

    input:
    path csv_files
    output:
    path("sample_sheet.csv"), emit: csv

    script:
    """
    csvtk concat ${csv_files} > sample_sheet.csv
    """
}

def projectList = params.project.toString().contains(',') ? params.project.tokenize(',') : [params.project]


workflow {

    ch_input = Channel.of(projectList).flatten()
    IRIDA_LINKER(ch_input)
    if (params.merge) {
        MERGE_SAMPLE_SHEET(IRIDA_LINKER.out.csv.collect())
    }
}