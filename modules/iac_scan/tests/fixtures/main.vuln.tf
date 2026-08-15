resource "aws_s3_bucket" "kyc_documents" {
  bucket = "alphanex-kyc"
  acl    = "public-read"  # VULN: documents KYC publics !
}

resource "aws_security_group" "trading_engine" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULN: PostgreSQL ouvert au monde
  }
}
