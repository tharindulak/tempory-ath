// ------------------------------------------------------------------------
//
// Copyright 2019 WSO2, Inc. (http://wso2.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// ------------------------------------------------------------------------

import ballerina/log;
import ballerina/mysql;
import ballerina/sql;
import cellery_hub_api/gen;
import ballerina/io;

public function getOrganization (string orgName) returns json|error {
    log:printDebug("Performing data retreival on REGISTRY_ORGANIZATION table, Org name : " + orgName);
    table<record {}> res =  check connection -> select (GET_ORG_QUERY, gen:OrgResponse, orgName, loadToMemory = true);
    if (res.count() == 1) {
        gen:OrgResponse orgRes = check gen:OrgResponse.convert(res.getNext());
        json resPayload = check json.convert(orgRes);
        log:printDebug("Fetching data for organization " +orgName+ ", from REGISTRY_ORGANIZATION is successful");
        return resPayload;       
    } else {
        log:printDebug("The requested organization \'" +orgName+ "\' is not found in REGISTRY_ORGANIZATION");
        return null;
    }
}

public function insertOrganization (string author, gen:OrgCreateRequest createOrgsBody) returns error? {
    log:printDebug ("Performing insertion on REGISTRY_ORGANIZATION table, Org name : " + createOrgsBody.orgName);
    sql:UpdateResult res = check connection -> update (ADD_ORG_QUERY, createOrgsBody.orgName, createOrgsBody.description,
                                            createOrgsBody.websiteUrl, createOrgsBody.defaultVisibility, author);
}

public function getOrganizationCount(string userId) returns int | error {
    log:printDebug("Retriving number organiations for user : " + userId);
    table< record {}> selectRet = check connection->select(GET_ORG_COUNT_FOR_USER, (), userId);
    json jsonConversionRet = check json.convert(selectRet);
    log:printDebug("Response from organization count query from DB: " + check string.convert(jsonConversionRet));
    int value = check int.convert(jsonConversionRet[0]["COUNT(ORG_NAME)"]);
    log:printDebug("Count organiations for user : " + userId + ": " + value);
    return value;
}