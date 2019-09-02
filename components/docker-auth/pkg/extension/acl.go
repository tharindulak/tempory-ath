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

package extension

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/cesanta/docker_auth/auth_server/api"
	"log"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

func ValidateAccess(db *sql.DB, actions [] string, username string, repository string, labels api.Labels,
	execId string) (bool, error) {

	log.Printf("[%s] Required actions for the username are :%s", execId, actions)
	log.Printf("[%s] Received labels are :%s", execId, labels)

	isPullOnly := false
	if len(actions) == 1 && actions[0] == pullAction {
		log.Printf("[%s] Received a request for pull only action", execId)
		isPullOnly = true
	}

	log.Printf("[%s] Label map length : %d", execId, len(labels))
	if len(labels) < 1 {
		log.Printf("[%s] Not received any label", execId)
		return false, nil
	}

	if labels["isAuthSuccess"][0] == "true" {
		log.Printf("[%s] Validating access for authenticated user", execId)
	} else {
		if isPullOnly {
			log.Printf("[%s] Validating access for unauthenticated user for pull action", execId)
		} else {
			log.Printf("[%s] Denying access for unauthenticated user for push action", execId)
			return false, nil
		}
	}

	organization, image, err := getOrganizationAndImage(repository, execId)
	if err != nil {
		return false, err
	}
	log.Printf("[%s] Image name is declared as :%s\n", execId, image)
	if isPullOnly {
		log.Printf("[%s] Received a pulling task\n", execId)
		return isAuthorizedToPull(db, username, organization, image, execId)
	} else {
		log.Printf("[%s] Received a pushing task\n", execId)
		return isAuthorizedToPush(db, username, organization, execId)
	}
}

func getOrganizationAndImage(imageFullName string, execId string) (string, string, error) {
	tokens := strings.Split(imageFullName, "/")
	log.Printf("[%s] Organization and image info: %s\n", execId, tokens)
	if len(tokens) == 2 {
		log.Printf("[%s] Organization : %s, image : %s\n", execId, tokens[0], tokens[1])
		return tokens[0], tokens[1], nil
	} else {
		log.Printf("[%s] Organization and image info not found\n", execId)
		return "", "", errors.New("token length mismatched")
	}
}

func getImageVisibility(db *sql.DB, image string, organization string, execId string) (string, error) {
	log.Printf("[%s] Retrieving image visibility for image %s in organization %s\n", execId,
		image, organization)
	var visibility = ""
	results, err := db.Query(getVisibilityQuery, image, organization)
	defer func() {
		closeResultSet(results, "getImageVisibility", execId)
	}()
	if err != nil {
		log.Printf("[%s] Error while calling the mysql query getVisibilityQuery :%s\n", execId, err)
		return visibility, err
	}
	if results.Next() {
		err = results.Scan(&visibility)
		log.Printf("[%s] Visibility of the image %s/%s is found as %s from the db\n", execId, organization,
			image, visibility)
	} else {
		log.Printf("[%s] Visibility of the image %s/%s is not found in the db\n", execId, organization,
			image)
	}
	if err != nil {
		log.Printf("[%s] Error in retrieving the visibility for %s/%s from the database :%s\n", execId,
			organization, image, err)
		return visibility, err
	}
	return visibility, nil
}

func isUserAvailable(db *sql.DB, organization, user string, execId string) (bool, error) {
	log.Printf("[%s] Checking whether the user %s exists in the organization %s\n", execId, user, organization)
	results, err := db.Query(getUserAvailabilityQuery, user, organization)
	defer func() {
		closeResultSet(results, "isUserAvailable", execId)
	}()
	if err != nil {
		log.Printf("[%s] Error while calling the mysql query getUserAvailabilityQuery :%s\n", execId, err)
		return false, err
	}
	if results.Next() {
		log.Printf("[%s] User %s is available in the organization :%s\n", execId, user, organization)
		return true, nil
	} else {
		log.Printf("[%s] User %s is not available in the organization :%s\n", execId, user, organization)
		return false, nil
	}
}

func isAuthorizedToPull(db *sql.DB, user, organization, image string, execId string) (bool, error) {
	log.Printf("[%s] ACL is checking whether the user %s is authorized to pull the image %s in the "+
		" organization %s.\n", execId, user, image, organization)

	visibility, err := getImageVisibility(db, image, organization, execId)

	if err != nil {
		log.Printf("[%s] User %s is not authorized to pull the image %s/%s.\n", execId, user,
			organization, image)
		return false, fmt.Errorf("error occured while geting visibility of image %s/%s", organization, image)
	} else if strings.EqualFold(visibility, publicVisibility) {
		log.Printf("[%s] Visibility of the image %s/%s is public. Hence user %s is authorized to pull\n",
			execId, organization, image, user)
		return true, nil
	} else {
		log.Printf("[%s] Visibility is not public for image %s/%s to the user %s\n", execId, organization,
			image, user)
		// Check whether the username exists in the organization when a fresh image come and tries to push
		return isUserAvailable(db, organization, user, execId)
	}
}

func isAuthorizedToPush(db *sql.DB, user, organization string, execId string) (bool, error) {
	log.Printf("[%s] User %s is trying to push to organization :%s\n", execId, user, organization)
	results, err := db.Query(getUserRoleQuery, user, organization)
	defer func() {
		closeResultSet(results, "isAuthorizedToPush", execId)
	}()
	if err != nil {
		log.Printf("[%s] Error while calling the mysql query getUserRoleQuery :%s\n", execId, err)
		return false, err
	}
	if results.Next() {
		var userRole string
		// for each row, scan the result into our tag composite object
		err = results.Scan(&userRole)
		if err != nil {
			log.Printf("[%s] Error in retrieving the username role from the database :%s\n", execId, err)
			return false, err
		}
		log.Printf("[%s] User role is declared as %s\n", execId, userRole)
		if (userRole == userAdminRole) || (userRole == userPushRole) {
			log.Printf("[%s] User is allowed to push the image\n", execId)
			return true, nil
		} else {
			log.Printf("[%s] User does not have push rights\n", execId)
			return false, err
		}
	}
	return false, nil
}

func closeResultSet(r *sql.Rows, caller string, execId string) {
	if r != nil {
		err := r.Close()
		if err != nil {
			log.Printf("[%s] Error while closing result set in %s : %v\n", execId, caller, err)
		}
	}
}
