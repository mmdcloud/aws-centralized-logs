output "asg_lb" {
  value = module.asg_lb.lb_dns_name
}

output "ecs_lb" {
  value = module.ecs_lb.lb_dns_name
}

output "opensearch_arn" {
  value = module.opensearch.domain_arn
}