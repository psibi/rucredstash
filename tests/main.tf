terraform {
  required_version = "1.0.5"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 3.72.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "credstash" {
  description             = "Credstash key"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "credstash" {
  name          = "alias/credstash"
  target_key_id = aws_kms_key.credstash.key_id
}
