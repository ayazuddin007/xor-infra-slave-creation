#Tags for ec2 instance
locals {
    ec2_tags = {
        LOB = "cis"
        Environment = "${var.environment}"
        Name = "poc-test-slave"
    }
}
