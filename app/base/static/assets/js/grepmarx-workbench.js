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
            anchorLines = document.getElementById('anchor-line').innerText;
            anchorColStart = document.getElementById('anchor-col-start').innerText;
            anchorColEnd = document.getElementById('anchor-col-end').innerText;
            highLightCode(anchorLines, anchorColStart, anchorColEnd);
        }
    };
    reqOccurenceCode.open('GET', '/analysis/codeview/' + occurence_id);
    reqOccurenceCode.send();
}

// ------------ Code highlighting

function highLightCode(anchorLines, anchorColStart, anchorColEnd) {
    /* Get highlighting information from the current page */
    const language = document.getElementById('language').innerText;
    const highlightTheme = document.getElementById('highlight-theme').innerText;
    
    /* Highlight lines */
    const codeEnlight = document.getElementById('code-englight');
    EnlighterJS.enlight(codeEnlight, false); // Remove existing highlighting if any
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
    /* Stronger highlight inside columns numbers */
    highlightSpansBetweenColumns(anchorColStart, anchorColEnd);
}

/**
 * Constants for column-based highlighting
 */
const CONSTANTS = {
    HIGHLIGHT_CLASS: 'strong-highlight',
    DIV_CLASS: 'enlighter-special',
    LEADING_SPACES_REGEX: /^\s{2,}/,
    SPACES_SPLIT_REGEX: /^(\s{2,})(.*)/
};

/**
 * Function to highlight spans between specific columns
 * @param {number} startCol - Starting column for highlighting
 * @param {number} endCol - Ending column for highlighting
 */
function highlightSpansBetweenColumns(startCol, endCol) {
    const divs = Array.from(document.getElementsByClassName(CONSTANTS.DIV_CLASS));
    if (!divs.length) return;

    if (divs.length === 1) {
        divs[0].innerHTML = processSingleDiv(divs[0].innerHTML, startCol, endCol);
        return;
    }

    processMultipleDivs(divs, startCol, endCol);
}

/**
 * Process multiple divs for highlighting
 * @param {Element[]} divs - Array of div elements
 * @param {number} startCol - Starting column
 * @param {number} endCol - Ending column
 */
function processMultipleDivs(divs, startCol, endCol) {
    let isFirstSpanFound = false;
    divs.forEach((div, index) => {
        if (index === 0) {
            [div.innerHTML, isFirstSpanFound] = processDiv(div.innerHTML, startCol, null, true);
        } else if (index === divs.length - 1) {
            div.innerHTML = processLastDiv(div.innerHTML, endCol);
        } else {
            div.innerHTML = processAllSpans(div.innerHTML);
        }
    });
}

function processLastDiv(html, endCol) {
    return processDiv(html, null, endCol, false)[0];
}

/**
 * Process a single div with both start and end columns
 * @param {string} html - HTML content to process
 * @param {number} startCol - Starting column
 * @param {number} endCol - Ending column
 * @returns {string} Processed HTML
 */
function processSingleDiv(html, startCol, endCol) {
    return processDiv(html, startCol, endCol, true)[0];
}

/**
 * Process all spans in a div without column constraints
 * @param {string} html - HTML content to process
 * @returns {string} Processed HTML
 */
function processAllSpans(html) {
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = html;
    
    Array.from(tempDiv.getElementsByTagName('span')).forEach(span => {
        const text = span.textContent;
        if (hasLeadingSpaces(text)) {
            splitSpanAtSpaces(span);
        } else {
            span.classList.add(CONSTANTS.HIGHLIGHT_CLASS);
        }
    });
    
    return tempDiv.innerHTML;
}

/**
 * Check if text has leading spaces
 * @param {string} text - Text to check
 * @returns {boolean}
 */
function hasLeadingSpaces(text) {
    return CONSTANTS.LEADING_SPACES_REGEX.test(text);
}

/**
 * Calculate position information for text processing
 * @param {number} visibleCharCount - Current visible character count
 * @param {number} textLength - Length of text being processed
 * @returns {Object} Position information
 */
function calculatePosition(visibleCharCount, textLength) {
    return {
        startPos: visibleCharCount,
        endPos: visibleCharCount + textLength
    };
}

/**
 * Generic div processor that handles both start and end constraints
 * @param {string} html - HTML content to process
 * @param {number|null} startCol - Starting column (null if no start constraint)
 * @param {number|null} endCol - Ending column (null if no end constraint)
 * @param {boolean} isFirstDiv - Whether this is the first div being processed
 * @returns {[string, boolean]} Processed HTML and whether first span was found
 */
function processDiv(html, startCol, endCol, isFirstDiv) {
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = html;
    
    let isFirstSpanFound = false;
    let visibleCharCount = 1;
    
    const spans = Array.from(tempDiv.getElementsByTagName('span'));
    spans.forEach(span => {
        const text = span.textContent;
        const position = calculatePosition(visibleCharCount, text.length);
        
        if (endCol && position.startPos >= endCol) return;
        
        if (startCol !== null && !isFirstSpanFound && position.endPos > startCol) {
            isFirstSpanFound = true;
            const offset = startCol - position.startPos;
            
            if (offset > 0) {
                processSpanWithOffset(span, offset, endCol, position);
            } else {
                processSpanWithoutOffset(span, endCol, position);
            }
        } else if (startCol === null || isFirstSpanFound) {
            processMiddleOrEndSpan(span, endCol, position, startCol);
        }
        
        visibleCharCount = position.endPos;
    });
    
    return [tempDiv.innerHTML, isFirstSpanFound];
}

/**
 * Process span with offset from start column
 * @param {Element} span - Span element to process
 * @param {number} offset - Offset from start
 * @param {number|null} endCol - Ending column
 * @param {Object} position - Position information
 */
function processSpanWithOffset(span, offset, endCol, position) {
    const text = span.textContent;
    let beforeText = text.substring(0, offset);
    let afterText = text.substring(offset);
    
    if (endCol && position.endPos > endCol) {
        const endOffset = endCol - position.startPos;
        afterText = text.substring(offset, endOffset);
        const remainingText = text.substring(endOffset);
        createTripleSpans(span, beforeText, afterText, remainingText);
    } else {
        createSplitSpans(span, beforeText, afterText, true);
    }
}

/**
 * Process span without offset
 * @param {Element} span - Span element to process
 * @param {number|null} endCol - Ending column
 * @param {Object} position - Position information
 */
function processSpanWithoutOffset(span, endCol, position) {
    if (endCol && position.endPos > endCol) {
        const splitPosition = endCol - position.startPos;
        const highlightText = span.textContent.substring(0, splitPosition);
        const remainingText = span.textContent.substring(splitPosition);
        createSplitSpans(span, highlightText, remainingText, false);
    } else {
        span.classList.add(CONSTANTS.HIGHLIGHT_CLASS);
    }
}

/**
 * Process middle or end spans
 * @param {Element} span - Span element to process
 * @param {number|null} endCol - Ending column
 * @param {Object} position - Position information
 * @param {number|null} startCol - Starting column
 */
function processMiddleOrEndSpan(span, endCol, position, startCol) {
    if (endCol && position.endPos > endCol) {
        const splitPosition = endCol - position.startPos;
        const highlightText = span.textContent.substring(0, splitPosition);
        const remainingText = span.textContent.substring(splitPosition);
        createSplitSpans(span, highlightText, remainingText, false);
    } else {
        if (startCol === null && hasLeadingSpaces(span.textContent)) {
            splitSpanAtSpaces(span);
        } else {
            span.classList.add(CONSTANTS.HIGHLIGHT_CLASS);
        }
    }
}

/**
 * Split span at spaces and highlight second part
 * @param {Element} span - Span element to split
 */
function splitSpanAtSpaces(span) {
    const text = span.textContent;
    const match = text.match(CONSTANTS.SPACES_SPLIT_REGEX);
    if (!match) return;
    createSplitSpans(span, match[1], match[2], true);
}

/**
 * Create split spans with proper classes
 * @param {Element} originalSpan - Original span element
 * @param {string} firstText - Text for first span
 * @param {string} secondText - Text for second span
 * @param {boolean} highlightSecond - Whether to highlight second span
 */
function createSplitSpans(originalSpan, firstText, secondText, highlightSecond) {
    const parent = originalSpan.parentNode;
    const baseClass = originalSpan.className.replace(` ${CONSTANTS.HIGHLIGHT_CLASS}`, '');
    
    createSpan(parent, firstText, baseClass, !highlightSecond, originalSpan);
    createSpan(parent, secondText, baseClass, highlightSecond, originalSpan);
    
    parent.removeChild(originalSpan);
}

/**
 * Create triple spans for complex cases
 * @param {Element} originalSpan - Original span element
 * @param {string} firstText - Text for first span
 * @param {string} middleText - Text for middle span
 * @param {string} lastText - Text for last span
 */
function createTripleSpans(originalSpan, firstText, middleText, lastText) {
    const parent = originalSpan.parentNode;
    const baseClass = originalSpan.className.replace(` ${CONSTANTS.HIGHLIGHT_CLASS}`, '');
    
    createSpan(parent, firstText, baseClass, false, originalSpan);
    createSpan(parent, middleText, baseClass, true, originalSpan);
    createSpan(parent, lastText, baseClass, false, originalSpan);
    
    parent.removeChild(originalSpan);
}

/**
 * Create a single span element
 * @param {Element} parent - Parent element
 * @param {string} text - Text content
 * @param {string} baseClass - Base CSS class
 * @param {boolean} highlight - Whether to highlight the span
 * @param {Element} referenceNode - Reference node for insertion
 */
function createSpan(parent, text, baseClass, highlight, referenceNode) {
    if (!text) return;
    
    const span = document.createElement('span');
    span.className = highlight ? `${baseClass} ${CONSTANTS.HIGHLIGHT_CLASS}` : baseClass;
    span.textContent = text;
    parent.insertBefore(span, referenceNode);
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



