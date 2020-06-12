package server

import (
	"github.com/gogo/protobuf/types"
	"github.com/pachyderm/pachyderm/src/client"
	"github.com/pachyderm/pachyderm/src/client/auth"
	"github.com/pachyderm/pachyderm/src/client/pfs"
	"github.com/pachyderm/pachyderm/src/client/pkg/errors"
	"github.com/pachyderm/pachyderm/src/client/pkg/grpcutil"
	"github.com/pachyderm/pachyderm/src/server/pkg/serviceenv"
	"golang.org/x/net/context"
)

var _ APIServer = &authedAPIServer{}

type authedAPIServer struct {
	APIServer
	env *serviceenv.ServiceEnv
}

func newAuthed(inner APIServer, env *serviceenv.ServiceEnv) *authedAPIServer {
	return &authedAPIServer{
		APIServer: inner,
		env:       env,
	}
}

func (a *authedAPIServer) CopyFile(ctx context.Context, req *pfs.CopyFileRequest) (response *types.Empty, retErr error) {
	src, dst := req.Src, req.Dst
	// Validate arguments
	if src == nil {
		return nil, errors.New("src cannot be nil")
	}
	if src.Commit == nil {
		return nil, errors.New("src commit cannot be nil")
	}
	if src.Commit.Repo == nil {
		return nil, errors.New("src commit repo cannot be nil")
	}
	if dst == nil {
		return nil, errors.New("dst cannot be nil")
	}
	if dst.Commit == nil {
		return nil, errors.New("dst commit cannot be nil")
	}
	if dst.Commit.Repo == nil {
		return nil, errors.New("dst commit repo cannot be nil")
	}

	// authorization
	if err := a.checkIsAuthorized(ctx, src.Commit.Repo, auth.Scope_READER); err != nil {
		return nil, err
	}
	if err := a.checkIsAuthorized(ctx, dst.Commit.Repo, auth.Scope_WRITER); err != nil {
		return nil, err
	}
	if err := checkFilePath(dst.Path); err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *authedAPIServer) getAuth(ctx context.Context) client.AuthAPIClient {
	return a.env.GetPachClient(ctx)
}

func (a *authedAPIServer) checkIsAuthorized(ctx context.Context, r *pfs.Repo, s auth.Scope) error {
	client := a.getAuth(ctx)
	me, err := client.WhoAmI(ctx, &auth.WhoAmIRequest{})
	if auth.IsErrNotActivated(err) {
		return nil
	}
	req := &auth.AuthorizeRequest{Repo: r.Name, Scope: s}
	resp, err := client.Authorize(ctx, req)
	if err != nil {
		return errors.Wrapf(grpcutil.ScrubGRPC(err), "error during authorization check for operation on \"%s\"", r.Name)
	}
	if !resp.Authorized {
		return &auth.ErrNotAuthorized{Subject: me.Username, Repo: r.Name, Required: s}
	}
	return nil
}
