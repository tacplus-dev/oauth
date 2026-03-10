package internal

import (
	"context"
	"sort"
	"sync"
	"time"

	servicemanager "gitlab.com/secondstarcavalier/controlplane/services/sentinel/tacplus/service-manager"
	hz "gitlab.com/secondstarcavalier/controlplane/services/sentinel/tacplus/types/common/hazelcast"
	kernel_pb "gitlab.com/secondstarcavalier/controlplane/services/sentinel/tacplus/types/services/kernel"
	pb "gitlab.com/secondstarcavalier/controlplane/services/sentinel/tacplus/types/services/sentinel"
	"gitlab.com/secondstarcavalier/controlplane/services/sentinel/tacplus/wrappers/backends"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Service implements SentinelServiceServer and the service-manager Handler interface.
type Service struct {
	pb.UnimplementedSentinelServiceServer
	admin kernel_pb.ClusterStateBackendServiceClient
}

// NewHandler creates a new Handler.
// This is the entry-point factory called by the generated ServiceManager.
func NewHandler(bc *backends.Backends) (servicemanager.Handler, error) {
	s := &Service{}
	if err := s.Init(bc); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) GetGrpcImpl() pb.SentinelServiceServer {
	return s
}

func (s *Service) Init(bc *backends.Backends) error {
	s.admin = bc.Services().ClusterState().BackendStub()
	return nil
}

func (s *Service) HandleConfig(_ *pb.Config) error {
	return nil
}

func (s *Service) Shutdown(_ context.Context) {}

func (s *Service) WatchDashboard(req *pb.WatchDashboardRequest, stream pb.SentinelService_WatchDashboardServer) error {
	interval := req.GetIntervalSeconds()
	if interval < 1 {
		interval = 5
	}
	if interval > 60 {
		interval = 60
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// Send initial snapshot immediately.
	dash, err := s.GetDashboard(stream.Context(), nil)
	if err != nil {
		return err
	}
	if err := stream.Send(dash); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
			dash, err := s.GetDashboard(stream.Context(), nil)
			if err != nil {
				return err
			}
			if err := stream.Send(dash); err != nil {
				return err
			}
		}
	}
}

func (s *Service) GetClusterInfo(ctx context.Context, _ *emptypb.Empty) (*hz.AdminClusterInfo, error) {
	return s.admin.GetClusterInfo(ctx, &emptypb.Empty{})
}

func (s *Service) GetClusterHealth(ctx context.Context, _ *emptypb.Empty) (*hz.AdminClusterHealth, error) {
	return s.admin.GetClusterHealth(ctx, &emptypb.Empty{})
}

func (s *Service) GetNodeMetrics(ctx context.Context, _ *emptypb.Empty) (*pb.NodeMetricsResponse, error) {
	resp, err := s.admin.GetAllNodeMetrics(ctx, &kernel_pb.NodeMetricsGetAllRequest{})
	if err != nil {
		return nil, err
	}
	items := make([]*hz.AdminNodeMetrics, 0, len(resp.GetEntries()))
	for _, v := range resp.GetEntries() {
		items = append(items, v)
	}
	return &pb.NodeMetricsResponse{Items: items}, nil
}

func (s *Service) GetGrpcStats(ctx context.Context, _ *emptypb.Empty) (*pb.GrpcStatsResponse, error) {
	resp, err := s.admin.GetAllGrpcStats(ctx, &kernel_pb.GrpcStatsGetAllRequest{})
	if err != nil {
		return nil, err
	}
	items := make([]*hz.AdminGrpcStats, 0, len(resp.GetEntries()))
	for _, v := range resp.GetEntries() {
		items = append(items, v)
	}
	return &pb.GrpcStatsResponse{Items: items}, nil
}

func (s *Service) GetPersistenceStatus(ctx context.Context, _ *emptypb.Empty) (*pb.PersistenceStatusResponse, error) {
	resp, err := s.admin.GetAllPersistenceStatus(ctx, &kernel_pb.PersistenceStatusGetAllRequest{})
	if err != nil {
		return nil, err
	}
	items := make([]*hz.AdminPersistenceStatus, 0, len(resp.GetEntries()))
	for _, v := range resp.GetEntries() {
		items = append(items, v)
	}
	return &pb.PersistenceStatusResponse{Items: items}, nil
}

func (s *Service) GetNetworkStats(ctx context.Context, _ *emptypb.Empty) (*pb.NetworkStatsResponse, error) {
	resp, err := s.admin.GetAllNetworkStats(ctx, &kernel_pb.NetworkStatsGetAllRequest{})
	if err != nil {
		return nil, err
	}
	items := make([]*hz.AdminNetworkStats, 0, len(resp.GetEntries()))
	for _, v := range resp.GetEntries() {
		items = append(items, v)
	}
	return &pb.NetworkStatsResponse{Items: items}, nil
}

func (s *Service) GetThreadInfo(ctx context.Context, _ *emptypb.Empty) (*pb.ThreadInfoResponse, error) {
	resp, err := s.admin.GetAllThreadInfo(ctx, &kernel_pb.ThreadInfoGetAllRequest{})
	if err != nil {
		return nil, err
	}
	items := make([]*hz.AdminThreadInfo, 0, len(resp.GetEntries()))
	for _, v := range resp.GetEntries() {
		items = append(items, v)
	}
	return &pb.ThreadInfoResponse{Items: items}, nil
}

func (s *Service) GetTokenCacheStats(ctx context.Context, _ *emptypb.Empty) (*pb.TokenCacheStatsResponse, error) {
	resp, err := s.admin.GetAllTokenCacheStats(ctx, &kernel_pb.TokenCacheStatsGetAllRequest{})
	if err != nil {
		return nil, err
	}
	items := make([]*hz.AdminTokenCacheStats, 0, len(resp.GetEntries()))
	for _, v := range resp.GetEntries() {
		items = append(items, v)
	}
	return &pb.TokenCacheStatsResponse{Items: items}, nil
}

func (s *Service) GetMapStats(ctx context.Context, _ *emptypb.Empty) (*pb.MapStatsResponse, error) {
	resp, err := s.admin.GetAllMapStats(ctx, &kernel_pb.MapStatsGetAllRequest{})
	if err != nil {
		return nil, err
	}
	items := make([]*hz.AdminMapStats, 0, len(resp.GetEntries()))
	for _, v := range resp.GetEntries() {
		items = append(items, v)
	}
	return &pb.MapStatsResponse{Items: items}, nil
}

func (s *Service) GetDashboard(ctx context.Context, _ *emptypb.Empty) (*pb.DashboardResponse, error) {
	dash := &pb.DashboardResponse{}
	var mu sync.Mutex
	var firstErr error

	setErr := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(9)

	go func() {
		defer wg.Done()
		v, err := s.admin.GetClusterInfo(ctx, &emptypb.Empty{})
		if err != nil {
			setErr(err)
			return
		}
		mu.Lock()
		dash.ClusterInfo = v
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		v, err := s.admin.GetClusterHealth(ctx, &emptypb.Empty{})
		if err != nil {
			setErr(err)
			return
		}
		mu.Lock()
		dash.ClusterHealth = v
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		resp, err := s.admin.GetAllNodeMetrics(ctx, &kernel_pb.NodeMetricsGetAllRequest{})
		if err != nil {
			setErr(err)
			return
		}
		items := make([]*hz.AdminNodeMetrics, 0, len(resp.GetEntries()))
		for _, v := range resp.GetEntries() {
			items = append(items, v)
		}
		mu.Lock()
		dash.NodeMetrics = items
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		resp, err := s.admin.GetAllGrpcStats(ctx, &kernel_pb.GrpcStatsGetAllRequest{})
		if err != nil {
			setErr(err)
			return
		}
		items := make([]*hz.AdminGrpcStats, 0, len(resp.GetEntries()))
		for _, v := range resp.GetEntries() {
			items = append(items, v)
		}
		mu.Lock()
		dash.GrpcStats = items
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		resp, err := s.admin.GetAllPersistenceStatus(ctx, &kernel_pb.PersistenceStatusGetAllRequest{})
		if err != nil {
			setErr(err)
			return
		}
		items := make([]*hz.AdminPersistenceStatus, 0, len(resp.GetEntries()))
		for _, v := range resp.GetEntries() {
			items = append(items, v)
		}
		mu.Lock()
		dash.PersistenceStatus = items
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		resp, err := s.admin.GetAllNetworkStats(ctx, &kernel_pb.NetworkStatsGetAllRequest{})
		if err != nil {
			setErr(err)
			return
		}
		items := make([]*hz.AdminNetworkStats, 0, len(resp.GetEntries()))
		for _, v := range resp.GetEntries() {
			items = append(items, v)
		}
		mu.Lock()
		dash.NetworkStats = items
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		resp, err := s.admin.GetAllThreadInfo(ctx, &kernel_pb.ThreadInfoGetAllRequest{})
		if err != nil {
			setErr(err)
			return
		}
		items := make([]*hz.AdminThreadInfo, 0, len(resp.GetEntries()))
		for _, v := range resp.GetEntries() {
			items = append(items, v)
		}
		mu.Lock()
		dash.ThreadInfo = items
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		resp, err := s.admin.GetAllTokenCacheStats(ctx, &kernel_pb.TokenCacheStatsGetAllRequest{})
		if err != nil {
			setErr(err)
			return
		}
		items := make([]*hz.AdminTokenCacheStats, 0, len(resp.GetEntries()))
		for _, v := range resp.GetEntries() {
			items = append(items, v)
		}
		mu.Lock()
		dash.TokenCacheStats = items
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		resp, err := s.admin.GetAllMapStats(ctx, &kernel_pb.MapStatsGetAllRequest{})
		if err != nil {
			setErr(err)
			return
		}
		items := make([]*hz.AdminMapStats, 0, len(resp.GetEntries()))
		for _, v := range resp.GetEntries() {
			items = append(items, v)
		}
		mu.Lock()
		dash.MapStats = items
		mu.Unlock()
	}()

	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	// Filter per-node stats to only include current cluster members.
	// Stale entries from restarted nodes (with old UUIDs) are removed.
	// Replace UUID node_ids with member addresses for display.
	if dash.ClusterInfo != nil {
		active := make(map[string]bool, len(dash.ClusterInfo.Members))
		addrMap := make(map[string]string, len(dash.ClusterInfo.Members))
		for _, m := range dash.ClusterInfo.Members {
			active[m.Uuid] = true
			addrMap[m.Uuid] = m.Address
		}
		dash.NodeMetrics = filterAndResolve(dash.NodeMetrics, active, addrMap)
		dash.GrpcStats = filterAndResolve(dash.GrpcStats, active, addrMap)
		dash.PersistenceStatus = filterAndResolve(dash.PersistenceStatus, active, addrMap)
		dash.NetworkStats = filterAndResolve(dash.NetworkStats, active, addrMap)
		dash.ThreadInfo = filterAndResolve(dash.ThreadInfo, active, addrMap)
		dash.TokenCacheStats = filterAndResolve(dash.TokenCacheStats, active, addrMap)
	}

	return dash, nil
}

type nodeIDAccessor interface {
	GetNodeId() string
}

// filterAndResolve filters per-node items to active members, replaces UUID
// node_ids with member addresses, and sorts by address for stable display order.
func filterAndResolve[T nodeIDAccessor](items []T, active map[string]bool, addrMap map[string]string) []T {
	filtered := make([]T, 0, len(active))
	for _, item := range items {
		if !active[item.GetNodeId()] {
			continue
		}
		// Replace UUID node_id with member address
		if addr, ok := addrMap[item.GetNodeId()]; ok {
			setNodeID(item, addr)
		}
		filtered = append(filtered, item)
	}
	// Sort by node_id (now address) for stable ordering
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].GetNodeId() < filtered[j].GetNodeId()
	})
	return filtered
}

// setNodeID replaces the node_id field on any of the admin stats types.
func setNodeID(item any, id string) {
	switch v := item.(type) {
	case *hz.AdminNodeMetrics:
		v.NodeId = id
	case *hz.AdminGrpcStats:
		v.NodeId = id
	case *hz.AdminPersistenceStatus:
		v.NodeId = id
	case *hz.AdminNetworkStats:
		v.NodeId = id
	case *hz.AdminThreadInfo:
		v.NodeId = id
	case *hz.AdminTokenCacheStats:
		v.NodeId = id
	}
}
