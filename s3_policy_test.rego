package aws.s3

test_versioning_required {
    deny[msg] if {
        "resource": {
            "type": "aws_s3_bucket",
            "settings": {
                "versioning": false,
                "encryption": true
            }
        }
    }
}

test_encryption_required {
    deny[msg] if {
        "resource": {
            "type": "aws_s3_bucket",
            "settings": {
                "versioning": true,
                "encryption": false
            }
        }
    }
}
