package org_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestOrgHandlerCreateAndTeam(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := org.NewService(org.NewStore(pool), role.NewStore(pool))
	mux := http.NewServeMux()
	org.NewHandler(svc).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := baseserversv1connect.NewOrgServiceClient(http.DefaultClient, srv.URL)
	o, err := c.CreateOrganization(context.Background(), connect.NewRequest(&v1.CreateOrganizationRequest{Name: "Acme"}))
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if o.Msg.Organization.Id == "" || o.Msg.Organization.Name != "Acme" {
		t.Fatalf("bad org: %+v", o.Msg.Organization)
	}
	tm, err := c.CreateTeam(context.Background(), connect.NewRequest(&v1.CreateTeamRequest{OrgId: o.Msg.Organization.Id, Name: "Eng"}))
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	if tm.Msg.Team.OrgId != o.Msg.Organization.Id {
		t.Fatalf("team org mismatch: %+v", tm.Msg.Team)
	}
}

func TestOrgHandlerRejectsEmpty(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := org.NewService(org.NewStore(pool), role.NewStore(pool))
	mux := http.NewServeMux()
	org.NewHandler(svc).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := baseserversv1connect.NewOrgServiceClient(http.DefaultClient, srv.URL)
	_, err := c.CreateOrganization(context.Background(), connect.NewRequest(&v1.CreateOrganizationRequest{Name: ""}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (%v)", connect.CodeOf(err), err)
	}
}
