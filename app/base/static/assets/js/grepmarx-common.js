/**
 * Copyright (c) 2021 - present Orange Cyberdefense
 */

// ------------ New project form

function ajaxCreateProject(el) {
    document.getElementById("upload-progress-container").style.display = "flex";
    reqCreateProject = new XMLHttpRequest();
    reqCreateProject.upload.addEventListener("progress", function (e) {
        if (e.loaded == e.total) {
            animateUploadProgress();
        }
        else {
            var percent = Math.floor((e.loaded / e.total) * 100);
            updateUploadProgress(percent);
        }
    });
    reqCreateProject.onreadystatechange = function (el) {
        if (reqCreateProject.readyState === XMLHttpRequest.DONE) {
            if (reqCreateProject.status == 200) {
                document.location = "/analysis/scans/new/" + reqCreateProject.responseText;
            } else {
                resetUploadProgress();
                document.getElementById("upload-error-container").style.display = "flex";
                document.getElementById("upload-error").innerText = reqCreateProject.responseText;
            }
        }
    };
    reqCreateProject.open('POST', el.parentNode.action);
    reqCreateProject.send(new FormData(el.parentNode));
}

function animateUploadProgress() {
    var progress = document.getElementById("upload-progress");
    progress.setAttribute("style", "width:100%");
    progress.setAttribute("aria-valuenow", 100);
    progress.classList.add("progress-bar-striped");
    progress.classList.add("progress-bar-animated");
    progress.innerText = "Creating project...";
}

function updateUploadProgress(percent) {
    var progress = document.getElementById("upload-progress");
    progress.setAttribute("style", "width:" + percent + "%");
    progress.setAttribute("aria-valuenow", percent);
    progress.innerText = "Uploading " + percent + "%";
}

function resetUploadProgress() {
    var progress = document.getElementById("upload-progress");
    document.getElementById("upload-progress-container").style.display = "none";
    progress.classList.remove("progress-bar-striped");
    progress.classList.remove("progress-bar-animated");
    progress.setAttribute("style", "width:0%");
    progress.setAttribute("aria-valuenow", 0);
}

function showSelectedFile(el) {
    document.getElementById("source-archive-text").innerText = el.files[0].name;
}

// ------------ Switch dark mode

function switchTheme() {
    // Switch theme in the current page
    if (document.body.classList.contains("dark-mode")) {
        document.body.classList.remove("dark-mode");
        document.getElementById("main-navbar").classList.remove("navbar-gray-dark");
        document.getElementById("main-navbar").classList.remove("navbar-dark");
        document.getElementById("main-navbar").classList.add("navbar-white");
        document.getElementById("main-navbar").classList.add("navbar-light");

    } else {
        document.body.classList.add("dark-mode");
        document.getElementById("main-navbar").classList.remove("navbar-white");
        document.getElementById("main-navbar").classList.remove("navbar-light");
        document.getElementById("main-navbar").classList.add("navbar-gray-dark");
        document.getElementById("main-navbar").classList.add("navbar-dark");
    }
    // Change the preference server-side
    reqSwitchTheme = new XMLHttpRequest();
    reqSwitchTheme.open('GET', '/switch-theme');
    reqSwitchTheme.send();
}

// ------------ Projects auto-refresh

async function ajaxRefreshStatus(projectId) {
    while(true) {
        // https://stackoverflow.com/questions/951021/what-is-the-javascript-version-of-sleep
        await new Promise(r => setTimeout(r, 5000));
        reqProjectStatus = new XMLHttpRequest();
        reqProjectStatus.onreadystatechange = function () {
            if (reqProjectStatus.readyState === XMLHttpRequest.DONE) {
                state = reqProjectStatus.responseText;
                if (state != 2 && state != 4) {
                    document.location = '/projects';
                }
            }
        };
        reqProjectStatus.open('GET', '/projects/' + projectId + '/status');
        reqProjectStatus.send();
    }
}

// ------------ Asynchronous rule detail loading

function ajaxRuleDetails(el, ruleId) {
    reqRuleDetails = new XMLHttpRequest();
    reqRuleDetails.onreadystatechange = function () {
        if (reqRuleDetails.readyState === XMLHttpRequest.DONE) {
            var e = document.getElementById('modal-rule-details');
            e.innerHTML = reqRuleDetails.responseText;
        }
    };
    reqRuleDetails.open('GET', '/rules/details/' + ruleId);
    reqRuleDetails.send();
}

// ------------ Asynchronous rules sync

function ajaxSyncRules() {
    document.getElementById('overlay-modal-sync').classList.remove('d-none');
    document.getElementById('confirm-sync-button').setAttribute('disabled', 'true');
    reqRuleSync = new XMLHttpRequest();
    reqRuleSync.onreadystatechange = function () {
        if (reqRuleSync.readyState === XMLHttpRequest.DONE) {
            document.location = "/rules/sync_success"
        }
    };
    reqRuleSync.open('GET', '/rules/sync');
    reqRuleSync.send();
}

// ------------ Modals for remove confirmation

/**
 * Sets a location to redirect the user when a specific button is clicked.
 * 
 * @param {*} buttonId Identifier of the button
 * @param {*} location URL to redirect when the button is clicked
 */
 function setConfirmAction(buttonId, location) {
    btn = document.getElementById(buttonId);
    btn.onclick = function () {
        document.location = location;
    };
}

// ------------ Asynchronous vulnerable dependency detail loading

function ajaxVulnerableDependencyDetails(el, vulnDepId) {
    reVulnDepDetails = new XMLHttpRequest();
    reVulnDepDetails.onreadystatechange = function () {
        if (reVulnDepDetails.readyState === XMLHttpRequest.DONE) {
            var e = document.getElementById('modal-vulnerable-dependency-details');
            e.innerHTML = reVulnDepDetails.responseText;
        }
    };
    reVulnDepDetails.open('GET', '/analysis/dependencies/details/' + vulnDepId);
    reVulnDepDetails.send();
}

// ------------ Datatables with checkboxes

/**
 * Only checkboxes of the current datatable page are sent 
 * when the form is submitted. We have to maintain a hidden
 * input `datatable-selection` with a list of comma-separated
 * identifiers to circumvent this behavior.
 *
 * This is what the following functions are about.
 * 
 * Prerequisites:
 * - Works for only one datatable per HTML document
 * - The datatable variable name is `dataTable`
 * - The form contains a hidden field with `datatable-selection` as its id
 * 
 */

/**
 * Select a datatable line:
 * - Check the checkbox (eg. enable its `checked` attribute)
 * - Add the line identifier to the hidden list
 * 
 * @param {HTMLInputElement} el is the checkbox on the datatable line
 */
function selectLine(el) {
    el.checked = true;
    lst = document.getElementById("datatable-selection").value.split(",");
    lst.push(el.id);
    document.getElementById("datatable-selection").setAttribute("value", lst);
}

/**
 * Deselect a datatable line:
 * - Uncheck the checkbox (eg. disable its `checked` attribute)
 * - Remove the line identifier from the hidden list
 * 
 * @param {HTMLInputElement} el is the checkbox on the datatable line
 */
function deselectLine(el) {
    el.checked = false;
    lst = document.getElementById("datatable-selection").value.split(",");
    lst.splice(lst.indexOf(el.id), 1);
    document.getElementById("datatable-selection").setAttribute("value", lst);
}

/**
 * Toggle the selection state of a line based on the checkbox state.
 * - If the checkbox is checked, add the line identifier to the hidden list
 * - If the checkbox is unchecked, remove the line identifier from the hidden list
 * 
 * @param {HTMLInputElement} el is the checkbox on the datatable line
 */
function toggleLine(el) {
    if (el.checked) {
        selectLine(el);
    } else {
        deselectLine(el);
    }
}

/**
 * Check if a datatable line is selected according to the hidden list.
 * 
 * @param {HTMLInputElement} el is the checkbox on the datatable line
 */
function isSelectedLine(el) {
    lst = document.getElementById("datatable-selection").value.split(",");
    if (lst.indexOf(el.id) != -1) {
        return true;
    } else {
        return false;
    }
}

/**
 * Toggle all checkboxes on the current datatable's page., with
 * the following behavior :
 * - If all checkboxes are checked, uncheck them all
 * - Otherwise, check all checkboxes
 *
 */
function switchPageSelection() {
    //currentPage = dataTable.pages[dataTable.currentPage - 1]; Simple Datatable
    currentPage = dataTable.DataTable().rows({ page: 'current' }).nodes();
    allChecked = true;
    // are all checkboxes checked ?
    for (i = 0; i < currentPage.length; i++) {
        //checkbox = currentPage[i].firstChild.childNodes[1]; Simple Datatable
        checkbox = currentPage[i].children[0].childNodes[1];
        if (checkbox && !checkbox.checked) {
            allChecked = false;
            break;
        }
    }
    for (i = 0; i < currentPage.length; i++) {
        // checkbox = currentPage[i].firstChild.childNodes[1]; Simple Datatable
        checkbox = currentPage[i].children[0].childNodes[1];
        // check all checkboxes if it wasn't the case
        // otherwise, uncheck all checkboxes
        if (checkbox && !allChecked) {
            if (checkbox.checked) {
                // deselect already selected lines to keep the list consistency
                deselectLine(checkbox);
            }
            selectLine(checkbox);
        } else {
            deselectLine(checkbox);
        }
    }
}

/**
 * Refresh datatable line checkboxes' states (eg. their `checked` attribute) 
 * based on the hidden list data.
 */
function refreshSelectedLines() {
    allCheckboxes = document.getElementsByClassName("datatable-checkbox");
    for (i = 0; i < allCheckboxes.length; i++) {
        checkbox = allCheckboxes[i];
        // checkbox is checked if its identifier is in the list
        if (isSelectedLine(checkbox)) {
            checkbox.checked = true;
        } else {
            checkbox.checked = false;
        }
    }
}
