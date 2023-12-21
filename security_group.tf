# create security group for ec2 instance

resource "aws_security_group" "ec2_sg" {
  name        = "${var.client_name}-${var.environment}-${var.region_name}-slave_security_group1"
  description = "Allow Ports"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH port"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TCP Ports"
    from_port        = 8000
    to_port          = 9000
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.client_name}-${var.environment}-${var.region_name}-slave_security_group1"
    Owner = "WFL-DEVops"
  }
}
