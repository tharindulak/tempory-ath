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

function addOrgUserMapping(string userId, string orgName, string role) returns http:Response{
    var orgUserRes = db:insertOrgUserMapping(userId, orgName, role);
    if (orgUserRes is error) {
        log:printError(io:sprintf("Unexpected error occured while inserting org-user mapping. user : %s, Organization : %s", userId, orgName),
                                err = orgUserRes);
        return buildUnknownErrorResponse();
    } else {
        log:printDebug(io:sprintf("New organization \'%s\' added to REGISTRY_ORG_USER_MAPPING. Author : %s", orgName, userId));
        return buildSuccessResponse();
    }
}

function updatePayloadWithUserInfo (json payload, string field) returns error? {
    string userId = payload[field].toString();
    idp:UserInfo | error? modifiedRes = idp:getUserInfo(userId);
    if (modifiedRes is idp:UserInfo) {
        payload[field] = check json.convert(modifiedRes);
        log:printDebug(io:sprintf("Modifying response by adding userInformation for user ID : %s", userId));
    } else {
        payload[field] = {};
        log:printDebug(io:sprintf("Response modification failed : User information not found for user : \'%s\'", userId));
    }
}
