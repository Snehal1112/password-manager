package api

import "github.com/gorilla/mux"

// RouteInfo is one registered route: an HTTP method and its path template,
// exactly as gorilla/mux would match it (e.g. "/api/v1/vaults/{vault_name}/secrets").
type RouteInfo struct {
	Method string
	Path   string
}

// WalkRoutes enumerates every method+path pair registered on router. A route
// with no path template (e.g. a catch-all NotFoundHandler) or no explicit
// .Methods(...) call (some public subrouters register via bare HandleFunc)
// is skipped -- neither carries a meaningful method+path pair to document.
func WalkRoutes(router *mux.Router) ([]RouteInfo, error) {
	var routes []RouteInfo
	err := router.Walk(func(route *mux.Route, r *mux.Router, ancestors []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			return nil
		}
		for _, method := range methods {
			routes = append(routes, RouteInfo{Method: method, Path: tmpl})
		}
		return nil
	})
	return routes, err
}
