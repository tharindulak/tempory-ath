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
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/cellery-io/cellery-hub/components/docker-auth/pkg/auth"
	"github.com/cellery-io/cellery-hub/components/docker-auth/pkg/extension"
	"github.com/cesanta/docker_auth/auth_server/authn"
	"go.uber.org/zap"
)

type PluginAuthn struct {
	cfg *authn.PluginAuthnConfig
}

func (c *PluginAuthn) Authenticate(user string, password authn.PasswordString) (bool, authn.Labels, error) {
	fmt.Println(user, string(password))
	return doAuthentication(user, string(password))
}

func (c *PluginAuthn) Stop() {
}

func (c *PluginAuthn) Name() string {
	return "plugin auth"
}

var Authn PluginAuthn

func doAuthentication(user, incomingToken string) (bool, authn.Labels, error) {
	logger := zap.NewExample().Sugar()
	slogger := logger.Named("authentication")
	execId, err := extension.GetExecID()
	if err != nil {
		return false, nil, fmt.Errorf("error in generating the execId : %s", err)
	}

	slogger.Debugf("[%s] Username (%s) and password received from CLI", execId, user)

	tokenArray := strings.Split(incomingToken, ":")
	token := tokenArray[0]

	isPing := len(tokenArray) > 1 && tokenArray[1] == "ping"
	if isPing {
		slogger.Debugf("[%s] Ping request received", execId)
	}

	auth.Authenticate(user, token, execId)

	if !auth.Authenticate(user, token, execId) {
		slogger.Debugf("[%s] User access token failed to authenticate. Evaluating ping", execId)
		if isPing {
			return false, nil, fmt.Errorf("since this is a ping request, exiting with auth fail status " +
				"without passing to authorization filter")
		} else {
			slogger.Debugf("[%s] Failed authentication. But passing to authorization filter", execId)
			return true, addAuthenticationLabel(false, execId), nil
		}
	} else {
		slogger.Debugf("[%s] User successfully authenticated by validating token. Exiting with success "+
			"exit code", execId)
		return true, addAuthenticationLabel(true, execId), nil
	}
}

// resolves the authentication end point from the environment variables.
func resolveAuthenticationUrl(execId string) string {
	authServer := os.Getenv("AUTH_SERVER_URL")
	authenticationEP := os.Getenv("AUTHENTICATION_END_POINT")
	if len(authServer) == 0 {
		log.Printf("[%s] Error: AUTH_SERVER environment variable is empty\n", execId)
		return ""
	}
	if len(authenticationEP) == 0 {
		log.Printf("[%s] Error: AUTHENTICATION_END_POINT environment variable is empty\n", execId)
		return ""
	}
	return authServer + authenticationEP
}

func addAuthenticationLabel(isAuthenticated bool, execId string) authn.Labels {
	authResultString := strconv.FormatBool(isAuthenticated)
	label := make([]string, 1)
	label[0] = authResultString
	authLabels := authn.Labels{}
	authLabels["isAuthSuccess"] = label
	return authLabels
}
