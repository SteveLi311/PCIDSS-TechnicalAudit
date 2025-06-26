# PCI DSS Compliance Automation Toolkit - Architecture

## Project Overview

This project provides automated PCI DSS v4.0.1 compliance assessment tools for cloud environments, currently supporting AWS and Google Cloud Platform (GCP). The toolkit generates comprehensive compliance reports and audit trails for security assessments.

## System Architecture

### High-Level Components

```
PCI DSS Compliance Toolkit
├── AWS/                    # AWS-specific compliance checks
├── GCP/                    # GCP-specific compliance checks  
├── Shared Documentation/   # PCI DSS requirements and checklists
└── Reports/               # Generated compliance reports
```

### Current Architecture (Pre-Refactoring)

#### AWS Implementation
- **Mature Framework**: Well-established with shared libraries (`pci_html_report_lib.sh`)
- **Consolidated Reporting**: Unified HTML report generation
- **12 Requirement Scripts**: Individual scripts for each PCI DSS requirement
- **Interactive Reports**: Card-based, clickable HTML summaries

#### GCP Implementation  
- **Individual Scripts**: 8 separate requirement scripts with significant code duplication
- **Monolithic Architecture**: ~40-60% duplicate code across scripts (~8,100 total lines)
- **Inconsistent Interface**: Varying CLI options and output formats
- **Limited Shared Functionality**: Minimal code reuse between scripts

## Target Architecture (Post-Refactoring)

### GCP Refactored Framework

```
GCP/
├── shared_libs/
│   ├── gcp_pci_shared_lib.sh      # Core shared functions
│   ├── gcp_auth_lib.sh            # Authentication & scope handling
│   ├── gcp_reporting_lib.sh       # Report generation
│   └── gcp_validation_lib.sh      # Input validation & error handling
├── requirements/
│   ├── check_gcp_pci_requirement1.sh  # Refactored individual scripts
│   ├── check_gcp_pci_requirement2.sh  # Using shared libraries
│   └── ...
├── templates/
│   └── gcp_requirement_template.sh    # Template for new requirements
└── tests/
    ├── unit_tests/                     # Unit tests for shared libs
    └── integration_tests/              # End-to-end testing
```

## Technical Decisions

### Programming Languages
- **Shell Scripting (Bash)**: Primary language for cloud CLI integration
- **Python**: Report generation and data processing (AWS implementation)
- **HTML/CSS/JavaScript**: Interactive reporting interfaces

### Cloud Integration
- **AWS CLI**: For AWS resource assessment and data collection
- **Google Cloud CLI (gcloud)**: For GCP resource assessment
- **Service Account Authentication**: Recommended for production assessments

### Reporting Standards
- **PCI DSS v4.0.1**: Source of truth for compliance requirements
- **HTML Reports**: Primary output format with interactive features
- **JSON/Text**: Raw data outputs for integration with other tools

## Key Design Patterns

### Current AWS Pattern (Best Practice)
- **Shared Library Approach**: Common functions in reusable modules
- **Template-Based Generation**: Consistent report formatting
- **Modular Design**: Clear separation between assessment logic and presentation

### Target GCP Pattern (Refactoring Goal)
- **Plugin Architecture**: Easy addition of new requirements
- **Consistent CLI Interface**: Standardized command-line options across all scripts
- **Centralized Error Handling**: Common error management and logging
- **Shared Authentication**: Single authentication flow for all assessments

## Security Considerations

### Authentication
- **Service Accounts**: Recommended for automated assessments
- **Least Privilege Access**: Minimal permissions required for compliance checks
- **Credential Management**: Secure handling of authentication tokens

### Data Handling
- **No Persistent Storage**: Assessment data not retained after report generation
- **Local Processing**: All analysis performed locally or in controlled cloud environments
- **Audit Trails**: Comprehensive logging of all assessment activities

## Scalability & Extensibility

### Adding New Requirements
- **Template-Based**: Use requirement templates for consistent implementation
- **Shared Libraries**: Leverage common functionality for rapid development
- **Testing Framework**: Automated validation of new requirement implementations

### Multi-Cloud Support
- **Consistent Interface**: Similar CLI patterns across cloud providers
- **Shared Reporting**: Common report formats and styles
- **Pluggable Architecture**: Easy addition of new cloud platforms

## Dependencies

### External Dependencies
- **Cloud CLIs**: AWS CLI, Google Cloud CLI
- **System Tools**: Standard Unix utilities (jq, curl, etc.)
- **Python Libraries**: For advanced reporting features (AWS implementation)

### Internal Dependencies
- **PCI DSS Documentation**: Authoritative requirements source
- **Shared Libraries**: Common functionality across implementations
- **Report Templates**: Consistent output formatting

## Future Roadmap

### Phase 1: GCP Refactoring (Current)
- Eliminate code duplication in GCP scripts
- Implement shared library framework
- Standardize CLI interface and reporting

### Phase 2: Framework Unification
- Align AWS and GCP implementations
- Create cross-cloud shared libraries
- Unified reporting across platforms

### Phase 3: Platform Expansion
- Azure support
- Multi-cloud compliance dashboards
- Integration with enterprise security tools