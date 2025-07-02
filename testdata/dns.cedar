// This is a test file for the Cedar policy engine.
//
// This test file emulates the permissions of a DNS service with groups of
// administrators, webadmins, and users. It uses the namespace "DNS" for its actions,
// and principals.
@id("DNS.admins_policy")
permit (
    principal in DNS::Group::"admins",
    action in
        [DNS::Action::"create_host",
         DNS::Action::"delete_host",
         DNS::Action::"view_host",
         DNS::Action::"edit_host"],
    resource is Host
);

// Webadmins can edit, delete, or create hosts with a name label containing "webserver", and the IP
// address must be in the range 192.168.1.0/24
@id("DNS.webadmins_policy")
permit (
    principal in DNS::Group::"webadmins",
    action in
        [DNS::Action::"edit_host",
         DNS::Action::"delete_host",
         DNS::Action::"create_host"],
    resource is Host
)
when
{
    resource.nameLabels.contains("webserver") &&
    resource.ip.isInRange("192.168.1.0/24")
};

// Users can only view hosts
@id("DNS.users_policy")
permit (
    principal in DNS::Group::"users",
    action == DNS::Action::"view_host",
    resource is Host
);

// Charlie does not get to delete hosts, no matter what.
@id("DNS.charlie_forbid_delete_host_policy")
forbid (
    principal == DNS::User::"charlie",
    action == DNS::Action::"delete_host",
    resource is Host
);

// Admins can manipulate any IP address, even if it is a gw, a broadcast address,
// the network address, reserved. These three groups are unified as "restricted" IPs.
@id("DNS.admins_ip_policy")
permit (
    principal in DNS::Group::"admins",
    action in
        [DNS::Action::"ip_gw_management",
         DNS::Action::"ip_broadcast_management",
         DNS::Action::"ip_network_management",
         DNS::Action::"ip_reserved_management",
         DNS::Action::"ip_restricted_management"],
    resource is IPAddress
);

/// Admins can manage any IP in any network
@id("DNS.admins_ip_network_policy")
permit (
    principal in DNS::Group::"admins",
    action == DNS::Action::"ip_network_management",
    resource is IPAddress
);

/// Users can only manage IPs in specific networks
@id("DNS.users_ip_network_policy")
permit (
    principal in DNS::Group::"users",
    action == DNS::Action::"ip_network_management",
    resource is IPAddress
)
when
{
    resource.ip.isInRange("192.168.1.0/24") ||
    resource.ip.isInRange("10.0.0.0/8")
};

/// Admins can do whatever with labels.
@id("DNS.labels_admin_policy")
permit (
    principal in DNS::Group::"admins",
    action in
        [DNS::Action::"create_label",
         DNS::Action::"delete_label",
         DNS::Action::"view_label",
         DNS::Action::"edit_label"],
    resource is Label
);

// We also have a global super admin policy that allows the root super user
// to do anything to any resource.
@id("global.super_admin_allow_all_policy")
permit (
    principal == User::"super",
    action,
    resource
);
