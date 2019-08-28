/*
 * Copyright (c) 2019 WSO2 Inc. (http:www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http:www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package main

import (
	"fmt"
	"github.com/cellery-io/cellery-hub/components/docker-auth/pkg/auth"
	"github.com/cellery-io/cellery-hub/components/docker-auth/pkg/db"
	"github.com/cesanta/docker_auth/auth_server/api"
	"go.uber.org/zap"
	"log"
	"os"

	"github.com/cellery-io/cellery-hub/components/docker-auth/pkg/extension"
)

type PluginAuthz struct {
	Authz api.Authorizer
}

func (c *PluginAuthz) Stop() {
}

func (c *PluginAuthz) Name() string {
	return "plugin authz"
}

func (c *PluginAuthz) Authorize(ai *api.AuthRequestInfo) ([]string, error) {
	fmt.Printf("Received auth request info: %v", ai)
	return doAuthorize(ai)
}

var Authz PluginAuthz

func doAuthorize(ai *api.AuthRequestInfo) ([]string, error) {
	logger := zap.NewExample().Sugar()
	slogger := logger.Named("authorization")
	execId, err := extension.GetExecID()
	if err != nil {
		return nil, fmt.Errorf("error in generating the execId : %s", err)
	}
	slogger.Debugf("Authorization logic reached. User will be authorized")
	dbConnectionPool, err := db.GetDbConnectionPool()
	if err != nil {
		return nil, fmt.Errorf("error while establishing database connection pool")
	}
	authorized, err := auth.Authorization(dbConnectionPool, ai, execId)
	if err != nil {
		return nil, fmt.Errorf("error while executing authorization logic")
	}
	if !authorized {
		slogger.Debugf("[%s] User : %s is unauthorized for %s actions", execId, ai.Account, ai.Actions)
		return nil, nil
	} else {
		slogger.Debugf("[%s] User : %s is authorized for %s actions", execId, ai.Account, ai.Actions)
		return ai.Actions, nil
	}
}

// resolves the authorization end point from the environment variables.
func resolveAuthorizationUrl(execId string) string {
	authServer := os.Getenv("AUTH_SERVER_URL")
	authorizationEP := os.Getenv("AUTHORIZATION_END_POINT")
	if len(authServer) == 0 {
		log.Printf("[%s] Error: AUTH_SERVER environment variable is empty\n", execId)
		return ""
	}
	if len(authorizationEP) == 0 {
		log.Printf("[%s] Error: AUTHORIZATION_END_POINT environment variable is empty\n", execId)
		return ""
	}
	return authServer + authorizationEP
}
