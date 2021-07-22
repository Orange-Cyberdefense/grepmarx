/**
 * Copyright (c) 2021 - present Orange Cyberdefense
 */

// ------------ Split.js layout

Split(['#code', '#results'], {
    direction: 'vertical',
    sizes: [65, 35],
    gutterSize: 6,
    cursor: 'row-resize'
})
Split(['#vulnerabilities', '#occurences'], {
    sizes: [20, 80],
    gutterSize: 6,
    cursor: 'col-resize'
})

// ------------ Asynchronous elements loading

function ajaxOccurenceDetails(el, vulnerability_id) {
    reqOccurenceDetails = new XMLHttpRequest();
    reqOccurenceDetails.onreadystatechange = function() {
        if (reqOccurenceDetails.readyState === XMLHttpRequest.DONE) {
            var e = document.getElementById('modal-occurence-details');
            e.innerHTML = reqOccurenceDetails.responseText;
        }
    };
    reqOccurenceDetails.open('GET', '/analysis/occurence_details/' + vulnerability_id);
    reqOccurenceDetails.send();
}

function ajaxOccurencesTable(el, vulnerability_id) {
    if (el != null) {
        els = document.getElementsByClassName('workbench-list-group-item active');
        for (var i = 0; i < els.length; i++) {
            els[i].classList.remove("active");
        }
        el.classList.add("active");
    }
    document.getElementById('occurences-load').style.visibility = 'visible';
    reqOccurencesTable = new XMLHttpRequest();
    reqOccurencesTable.onreadystatechange = function() {
        if (reqOccurencesTable.readyState === XMLHttpRequest.DONE) {
            var e = document.getElementById('occurences-dyn');
            e.innerHTML = reqOccurencesTable.responseText;
            document.getElementById('occurences-load').style.visibility = 'hidden';
        }
    };
    reqOccurencesTable.open('GET', '/analysis/occurences_table/' + vulnerability_id);
    reqOccurencesTable.send();
}

function ajaxOccurenceCode(el, occurence_id) {
    if (el != null) {
        els = document.getElementsByClassName('tr-occurence active');
        for (var i = 0; i < els.length; i++) {
            els[i].classList.remove("active");
        }
        el.parentNode.classList.add("active");
    }
    reqOccurenceCode = new XMLHttpRequest();
    reqOccurenceCode.onreadystatechange = function () {
        if (reqOccurenceCode.readyState === XMLHttpRequest.DONE) {
            var e = document.getElementById('code');
            e.innerHTML = reqOccurenceCode.responseText;
            language = document.getElementById('language').innerText;
            anchorLines = document.getElementById('anchor-line').innerText;
            highlightTheme = document.getElementById('highlight-theme').innerText;
            highLightCode(language, anchorLines, highlightTheme);
        }
    };
    reqOccurenceCode.open('GET', '/analysis/codeview/' + occurence_id);
    reqOccurenceCode.send();
}

// ------------ Code highlighting

function highLightCode(language, anchorLines, highlightTheme) {
    const codeEnlight = document.getElementById('code-englight');
    EnlighterJS.enlight(codeEnlight, {
        theme: highlightTheme,
        toolbarTop: '',
        toolbarBottom: '',
        language: language,
        linehover: false,
        highlight: anchorLines
    });
    document.getElementsByClassName('enlighter-special')[0].scrollIntoView({
        block: 'center',
        behavior: 'smooth',
        inline: 'center'
    });
}

function highlightSelectedCode() {
    var context = document.querySelector(".enlighter");
    var instance = new Mark(context);
    instance.unmark();
    var selectedText = document.getSelection().toString();
    instance.mark(selectedText, {
        acrossElements: true,
        separateWordSearch: false,
        caseSensitive: true
    });
}