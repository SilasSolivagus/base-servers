package role

type Role struct {
	ID, OrgID, Name string
	Permissions     []string
}

// DefaultRoles 是每个组织建库时种下的三个基础角色。
var DefaultRoles = []struct {
	Name        string
	Permissions []string
}{
	{Name: "owner", Permissions: []string{"*"}},
	{Name: "admin", Permissions: []string{"org.manage", "member.manage", "role.manage"}},
	{Name: "member", Permissions: []string{"org.read"}},
}
