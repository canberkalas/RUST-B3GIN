pub fn load_rules() -> Vec<SecurityRule> {
    // Load security rules from a file or database
    // ...
}

pub fn check_rule(src_ip: &IpAddr, dst_port: u16, protocol: IpNextHeaderProtocols) -> bool {
    // Check against security rules
    // ...
}
