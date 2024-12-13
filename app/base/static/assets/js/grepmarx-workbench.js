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
    reqOccurenceDetails.onreadystatechange = function () {
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
    reqOccurencesTable.onreadystatechange = function () {
        if (reqOccurencesTable.readyState === XMLHttpRequest.DONE) {
            var e = document.getElementById('occurences-dyn');
            e.innerHTML = reqOccurencesTable.responseText;
            document.getElementById('occurences-load').style.visibility = 'hidden';
            // Display codeview for the first occurence in the table
            document.getElementsByClassName("occurences-table")[0].rows[1].cells[0].click();
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
            anchorColStart = document.getElementById('anchor-col-start').innerText;
            anchorColEnd = document.getElementById('anchor-col-end').innerText;
            highLightMore(anchorColStart, anchorColEnd);
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

/**
 * Highlights HTML content between specified columns across multiple elements
 * @param {number} startCol - Starting column for highlighting
 * @param {number} endCol - Ending column for highlighting
 */
function highLightMore(startCol, endCol) {
    // Get all elements with class 'enlighter-special'
    // Convert HTMLCollection to Array for forEach usage
    const elements = Array.from(document.getElementsByClassName('enlighter-special'));

    elements.forEach((element, index) => {
        let before, after;
        const isFirst = index === 0;
        const isLast = index === elements.length - 1;
        const content = element.innerHTML;

        // Different handling based on element position:
        // - First element: highlight from startCol to end
        // - Last element: highlight from start to endCol
        // - Middle elements: highlight entirely
        if (isFirst) {
            // For first line, split at startCol and highlight after
            const pos = findLastTagPosition(content, startCol) + 1;
            [before, after] = [content.slice(0, pos - 1), content.slice(pos - 1)];
            element.innerHTML = before + decorateSpansFromHtmlText(after);
        } else if (isLast) {
            // For last line, split at endCol and highlight before
            const pos = findLastTagPosition(content, endCol);
            [before, after] = [content.slice(0, pos - 1), content.slice(pos - 1)];
            element.innerHTML = decorateSpansFromHtmlText(before) + after;
        } else {
            // For intermediate lines, highlight everything
            element.innerHTML = decorateSpansFromHtmlText(content);
        }
    });
}

function findLastTagPosition(htmlString, targetColumn) {
    let visibleCharCount = 0;
    let actualPosition = 0;
    let inTag = false;
    let lastTagPosition = 0;

    // Loop through the string character by character
    for (let i = 0; i < htmlString.length; i++) {
        const char = htmlString[i];

        // Handle entering/exiting HTML tags
        if (char === '<') {
            inTag = true;
            lastTagPosition = i;
        } else if (char === '>') {
            inTag = false;
            continue;
        }

        // Count only visible characters (outside tags)
        if (!inTag) {
            visibleCharCount++;
        }

        // If we reach the target column
        if (visibleCharCount === targetColumn) {
            actualPosition = i;
            break;
        }
    }

    // Find the last opening tag before the current position
    for (let i = actualPosition; i >= 0; i--) {
        if (htmlString[i] === '<') {
            return i;
        }
    }

    return -1; // If no tag is found
}

function decorateSpansFromHtmlText(htmlString) {
  // First, handle the special case of leading spaces in first span
  const firstSpanRegex = /(<span(?:\s+class\s*=\s*["']([^"']*)["'])?[^>]*>)([\s\t]{2,})(.*?<\/span>)/;
  htmlString = htmlString.replace(firstSpanRegex, (match, openingTag, existingClasses, spaces, rest) => {
    const classAttr = existingClasses ? ` class="${existingClasses}"` : '';
    return `${openingTag}${spaces}</span><span${classAttr}>${rest}`;
  });

  // Then add strong-highlight class to all spans except the first one
  const spanRegex = /<span(?:\s+class\s*=\s*["']([^"']*)["'])?([^>]*)>/g;
  let isFirstSpan = true;

  return htmlString.replace(spanRegex, (match, existingClasses, otherAttributes) => {
    if (isFirstSpan) {
      isFirstSpan = false;
      return match;
    }

    if (existingClasses) {
      if (!existingClasses.includes('strong-highlight')) {
        return `<span class="${existingClasses} strong-highlight"${otherAttributes}>`;
      }
      return match;
    }
    return `<span class="strong-highlight"${otherAttributes}>`;
  });
}

// ------------ User selection highlighting

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



