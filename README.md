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

1.  **Detection**: **AWS GuardDuty** detects a `Recon:EC2/Portscan` finding against a monitored EC2 instance.
2.  **Alerting**: An **Amazon EventBridge** rule, listening for that specific finding, is triggered.
3.  **Invocation**: EventBridge invokes the `security-block-malicious-ip` **AWS Lambda** function. Failed invocations are sent to an SQS Dead-Letter Queue.
4.  **Response**: The Lambda function extracts the attacker's IP address from the event and adds it to the `security-malicious-ips` IP Set within **AWS WAF**, blocking it at the network edge.

***

## Technology Stack

* **Infrastructure as Code**: Terraform
* **Cloud Provider**: AWS
* **Security Services**: AWS GuardDuty, AWS WAF, AWS IAM
* **Compute**: AWS Lambda
* **Event-Driven Architecture**: Amazon EventBridge
* **Resilience**: Amazon SQS

***

## Deployment

**Prerequisites:**

1.  Create a dedicated S3 bucket and a DynamoDB table for the Terraform remote backend.
2.  Update the `main.tf` file's `backend "s3"` block with your bucket and table names.

**Steps:**

1.  **Initialize Terraform:**
    ```bash
    terraform init
    ```
2.  **Plan Deployment:**
    ```bash
    terraform plan
    ```
3.  **Apply Changes:**
    ```bash
    terraform apply
    ```