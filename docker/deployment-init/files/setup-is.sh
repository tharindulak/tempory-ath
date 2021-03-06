#!/usr/bin/env bash
# ------------------------------------------------------------------------
#
# Copyright 2019 WSO2, Inc. (http://wso2.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
#
# ------------------------------------------------------------------------

source idp-variables.sh

echo "Waiting for IdP to start"
while [[ true ]];
do
    PING_STATUS_CODE=$(curl -sL -k -w "%{http_code}" -I "${CELLERY_HUB_IDP_URL}/carbon/admin/login.jsp" -o /dev/null)
    if [[ "${PING_STATUS_CODE}" == "000" ]]
    then
        echo "Ping IdP - No Response"
    else
        echo "Ping IdP - Status Code ${PING_STATUS_CODE}"
    fi

    if [[ "${PING_STATUS_CODE}" == "200" ]]
    then
        break
    fi
    sleep 5
done

export -n create_google_body=$(cat create-google-idp.xml)
export -n create_github_body=$(cat create-github-idp.xml)
export -n create_oauth2_app_cellery_hub=$(cat create-oauth2-app-cellery-hub.xml)
export -n create_oauth2_app_cli=$(cat create-oauth2-app-cli.xml)
export -n update_cellery_hub_application=$(cat update-cellery-hub-application.xml)
export -n update_cli_application=$(cat update-cli-application.xml)

set -e

unset IFS
args=() i=0
for var in $(compgen -e); do



    if [[ $var == CELLERY_HUB_* ]] ;
    then
        export tempEnvVal=$(echo ${!var})
        export create_google_body=$(echo $create_google_body | sed "s#{$var}#${tempEnvVal}#g")
        export create_github_body=$(echo $create_github_body | sed "s#{$var}#${tempEnvVal}#g")
        export create_oauth2_app_cellery_hub=$(echo $create_oauth2_app_cellery_hub | sed "s#{$var}#${tempEnvVal}#g")
        export create_oauth2_app_cli=$(echo $create_oauth2_app_cli | sed "s#{$var}#${tempEnvVal}#g")
        export update_cellery_hub_application=$(echo $update_cellery_hub_application | sed "s#{$var}#${tempEnvVal}#g")
        export update_cli_application=$(echo $update_cli_application | sed "s#{$var}#${tempEnvVal}#g")

    fi
done


split_resluts(){
export BODY=$(echo $HTTP_RESPONSE | sed -e 's/HTTPSTATUS\:.*//g')
export STATUS=$(echo $HTTP_RESPONSE | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
}

echo_results () {
split_resluts
  if [ $STATUS -eq 200 ]; then
  tput setaf 2;
    echo $1
    tput sgr0;
  else
    tput setaf 1;
    echo "$2 , Status code : $STATUS"
    tput sgr0;
    echo "response from server: $BODY"
  fi
}


HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:addIdP" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data "$create_google_body" ${CELLERY_HUB_IDP_URL}/services/IdentityProviderMgtService.IdentityProviderMgtServiceHttpsSoap12Endpoint -k)

echo_results "Google IDP added successfully" "Error while adding Google IDP"

HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:addIdP" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data "$create_github_body" ${CELLERY_HUB_IDP_URL}/services/IdentityProviderMgtService.IdentityProviderMgtServiceHttpsSoap12Endpoint -k)

echo_results "Github IDP added successfully" "Error while adding Github IDP"

HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:registerOAuthApplicationData" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data "$create_oauth2_app_cli"l ${CELLERY_HUB_IDP_URL}/services/OAuthAdminService.OAuthAdminServiceHttpsSoap12Endpoint/ -k)

echo_results "CLI OAuth2 application added successfully" "Error while adding CLI OAuth2 application"

HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:registerOAuthApplicationData" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data "$create_oauth2_app_cellery_hub" ${CELLERY_HUB_IDP_URL}/services/OAuthAdminService.OAuthAdminServiceHttpsSoap12Endpoint/ -k)

echo_results "Cellery Hub application added successfully" "Error while adding Cellery hub OAuth2 application"

HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:createApplication" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data @create-cli-app.xml ${CELLERY_HUB_IDP_URL}/services/IdentityApplicationManagementService.IdentityApplicationManagementServiceHttpsSoap12Endpoint/ -k)

echo_results "CLI service provider created" "Error while creating CLI service provider"

HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:createApplication" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data @create-web-portal-app.xml ${CELLERY_HUB_IDP_URL}/services/IdentityApplicationManagementService.IdentityApplicationManagementServiceHttpsSoap12Endpoint/ -k)

echo_results "Cellery Hub Web Portal service provider created" "Error while creating Cellery Hub Web Portal service provider"

HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:updateApplication" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data "$update_cellery_hub_application" ${CELLERY_HUB_IDP_URL}/services/IdentityApplicationManagementService.IdentityApplicationManagementServiceHttpsSoap12Endpoint/ -k)

echo_results "Cellery Hub service provider updated with OAuth2 app" "Error while updating Cellery Hub service provider with OAuth2 app"

HTTP_RESPONSE=$(curl --silent --write-out "HTTPSTATUS:%{http_code}" --header "Content-Type: application/soap+xml;charset=UTF-8" --header "SOAPAction:urn:updateApplication" -u ${CELLERY_HUB_IDP_ADMIN_USERNAME}:${CELLERY_HUB_IDP_ADMIN_PASSWORD} --data "$update_cli_application" ${CELLERY_HUB_IDP_URL}/services/IdentityApplicationManagementService.IdentityApplicationManagementServiceHttpsSoap12Endpoint/ -k)

echo_results "CLI service provider updated with OAuth2 app" "Error while updating CLI service provider with OAuth2 app"

set +e
