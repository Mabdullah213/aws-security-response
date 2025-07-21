# Automated Cloud Security Response on AWS

This project deploys a professional-grade, event-driven security workflow on AWS using Terraform. It automatically detects and blocks malicious IP addresses that perform reconnaissance scans, demonstrating a modern, resilient, and secure approach to cloud infrastructure management.

***

## Key Features & Professional Practices

* **Event-Driven & Serverless**: Leverages AWS Lambda and Amazon EventBridge for an immediate, cost-effective response to threats without managing any server infrastructure.
* **Infrastructure as Code (IaC)**: The entire stack is defined in Terraform, enabling automated, repeatable, and version-controlled deployments.
* **Security by Design**:
    * **Principle of Least Privilege**: The Lambda function operates under a fine-grained, custom IAM policy, granting only the precise permissions required to perform its task.
    * **Secure Configuration**: Function code is decoupled from configuration. The WAF IP Set name and scope are passed securely via Lambda environment variables, allowing the function to be used across different environments without code changes.
* **Operational Resilience**:
    * **Fault Tolerance**: An SQS Dead-Letter Queue (DLQ) is configured to capture any failed Lambda invocations, ensuring security events are never lost and are available for analysis.
* **Collaborative & Scalable Infrastructure**:
    * **Remote State Management**: The Terraform configuration is structured to use an S3 backend with a DynamoDB table for state locking, the industry standard for managing infrastructure in a team environment or CI/CD pipeline.

***

## Architecture

```mermaid
graph TD;
    subgraph "Detection & Alerting"
        GuardDuty["AWS GuardDuty"];
        EventBridge["Amazon EventBridge Rule"];
    end

    subgraph "Invocation & Response"
        Lambda["fa:fa-bolt AWS Lambda<br/>security-block-malicious-ip"];
        WAF["fa:fa-shield-alt AWS WAF<br/>security-malicious-ips"];
        DLQ["fa:fa-bug SQS Dead-Letter Queue"];
    end

    GuardDuty -- "Generates 'Recon:EC2/Portscan' Finding" --> EventBridge;
    EventBridge -- "Invokes Function" --> Lambda;
    Lambda -- "Blocks Malicious IP" --> WAF;
    Lambda -.->|On Failure| DLQ;

    style Lambda fill:#FF9900,stroke:#333,stroke-width:2px;
    style WAF fill:#232F3E,stroke:#FF9900,stroke-width:2px,color:#fff;
    style GuardDuty fill:#232F3E,stroke:#FF9900,stroke-width:2px,color:#fff;
    style EventBridge fill:#232F3E,stroke:#FF9900,stroke-width:2px,color:#fff;
    style DLQ fill:#B30000,stroke:#333,stroke-width:2px,color:#fff;
