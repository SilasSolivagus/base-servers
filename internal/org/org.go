package org

type Organization struct {
	ID, Name, ParentID string
}

type Team struct {
	ID, OrgID, Name string
}
