package aws.s3

deny[msg] if {
    input.resource.type == "aws_s3_bucket"
    not input.resource.settings.versioning
    msg := "S3 buckets must have versioning enabled"
}

deny[msg] if {
    input.resource.type == "aws_s3_bucket"
    not input.resource.settings.encryption
    msg := "S3 buckets must have encryption enabled"
}
