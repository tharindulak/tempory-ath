/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import CheckCircle from "@material-ui/icons/CheckCircle";
import CircularProgress from "@material-ui/core/CircularProgress";
import Close from "@material-ui/icons/Close";
import Error from "@material-ui/icons/Error";
import IconButton from "@material-ui/core/IconButton";
import Info from "@material-ui/icons/Info";
import NotificationUtils from "../../utils/common/notificationUtils";
import React from "react";
import Snackbar from "@material-ui/core/Snackbar/Snackbar";
import StateHolder from "./state/stateHolder";
import Warning from "@material-ui/icons/Warning";
import withGlobalState from "./state";
import {withStyles} from "@material-ui/core/styles";
import * as PropTypes from "prop-types";

const styles = (theme) => ({
    progressOverlayContainer: {
        position: "absolute",
        zIndex: 9999,
        top: 0,
        left: 0,
        width: "100%",
        height: "100%"
    },
    progressOverlay: {
        position: "relative",
        display: "grid",
        top: 0,
        left: 0,
        width: "100%",
        height: "100%",
        backgroundColor: "rgb(0, 0, 0, 0.5)"
    },
    progress: {
        textAlign: "center",
        margin: "auto"
    },
    progressIndicator: {
        margin: theme.spacing.unit * 2
    },
    progressContent: {
        fontSize: "large",
        fontWeight: 500,
        width: "100%",
        color: "#ffffff"
    },
    snackbarIcon: {
        fontSize: "1.5em"
    },
    snackbarMessageContainer: {
        display: "flex",
        alignItems: "center"
    },
    snackbarMessage: {
        paddingLeft: theme.spacing.unit
    }
});

class NotificationAdditions extends React.Component {

    constructor(props) {
        super(props);

        const loadingState = props.globalState.get(StateHolder.LOADING_STATE);
        const notificationState = props.globalState.get(StateHolder.NOTIFICATION_STATE);

        this.state = {
            loadingState: {
                isLoading: loadingState.loadingOverlayCount > 0,
                message: loadingState.message
            },
            notificationState: {
                isOpen: notificationState.isOpen,
                message: notificationState.message,
                notificationLevel: notificationState.notificationLevel
            }
        };

        props.globalState.addListener(StateHolder.LOADING_STATE, this.handleLoadingStateChange);
        props.globalState.addListener(StateHolder.NOTIFICATION_STATE, this.handleNotificationStateChange);
    }

    handleLoadingStateChange = (loadingStateKey, oldState, newState) => {
        this.setState({
            loadingState: {
                isLoading: newState.loadingOverlayCount > 0,
                message: newState.message
            }
        });
    };

    handleNotificationStateChange = (notificationStateKey, oldState, newState) => {
        this.setState({
            notificationState: {
                isOpen: newState.isOpen,
                message: newState.message,
                notificationLevel: newState.notificationLevel
            }
        });
    };

    handleNotificationClose = () => {
        const {globalState} = this.props;
        NotificationUtils.closeNotification(globalState);
    };

    generateSnackbarMessage = () => {
        const {classes} = this.props;
        const {notificationState} = this.state;

        let Icon;
        switch (notificationState.notificationLevel) {
            case NotificationUtils.Levels.SUCCESS:
                Icon = CheckCircle;
                break;
            case NotificationUtils.Levels.WARNING:
                Icon = Warning;
                break;
            case NotificationUtils.Levels.ERROR:
                Icon = Error;
                break;
            default:
                Icon = Info;
        }

        return (
            <span className={classes.snackbarMessageContainer}>
                <Icon className={classes.snackbarIcon}/>
                <span className={classes.snackbarMessage}>{notificationState.message}</span>
            </span>
        );
    };

    render() {
        const {classes} = this.props;
        const {loadingState, notificationState} = this.state;
        return (
            <React.Fragment>
                <div className={classes.progressOverlayContainer} style={{
                    display: loadingState.isLoading ? "block" : "none"
                }}>
                    <div className={classes.toolbar}/>
                    <div className={classes.progressOverlay}>
                        <div className={classes.progress}>
                            <CircularProgress className={classes.progressIndicator} thickness={4.5} size={45}/>
                            <div className={classes.progressContent}>
                                {loadingState.message ? loadingState.message : "Loading"}...
                            </div>
                        </div>
                    </div>
                </div>
                <Snackbar open={notificationState.isOpen} ContentProps={{"aria-describedby": "main-notification"}}
                    anchorOrigin={{
                        vertical: "bottom",
                        horizontal: "left"
                    }}
                    onClose={this.handleNotificationClose} message={this.generateSnackbarMessage()}
                    autoHideDuration={5000}
                    action={[
                        <IconButton key={"close"} aria-label={"Close"} color={"inherit"}
                            onClick={this.handleNotificationClose}>
                            <Close/>
                        </IconButton>
                    ]}
                />
            </React.Fragment>
        );
    }

}

NotificationAdditions.propTypes = {
    globalState: PropTypes.instanceOf(StateHolder),
    classes: PropTypes.object.isRequired
};

export default withStyles(styles)(withGlobalState(NotificationAdditions));
