import "tfplan"

# Define allowed instance types
allowed_instance_types = {
  "t2.small": true,
  "t2.medium": true,
  "m5.large": true,
}

# Define allowed instance AMI
allowed_instance_ami = {
  "ami-0c94855ba95c71c99": true,
  "ami-09f0c1e1d35785a38": true,
}

# Check if any EC2 instance has internet access
deny[msg] {
  instance := tfplan.resource_changes.aws_instance
  instance.type == "aws_instance"
  instance.change.after.security_groups.*.cidr_blocks contains "0.0.0.0/0"
  msg = "EC2 instance should not have internet access"
}

# Check if the instance type is allowed
deny[msg] {
  instance := tfplan.resource_changes.aws_instance
  instance.type == "aws_instance"
  instance.change.after.instance_type not in allowed_instance_types
  msg = sprintf("EC2 instance type '%v' is not allowed", [instance.change.after.instance_type])
}

# Check if the instance AMI is allowed
deny[msg] {
  instance := tfplan.resource_changes.aws_instance
  instance.type == "aws_instance"
  instance.change.after.ami not in allowed_instance_ami
  msg = sprintf("EC2 instance AMI '%v' is not allowed", [instance.change.after.ami])
}
