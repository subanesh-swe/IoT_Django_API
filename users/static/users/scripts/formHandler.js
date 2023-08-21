const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

function formSubmitHandler(event, formId) {
    event.preventDefault();
    const formData = new FormData(document.getElementById(formId));
    console.log("request data => " + JSON.stringify(formData));
    fetch(window.location.pathname, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRFToken': csrfToken,
        },
        body: new URLSearchParams(formData).toString()
    })
        .then(response => response.json())
        .then(data => {
            console.log("response data => " + JSON.stringify(data));
            function stringifyAlert(rawAlert) {
                var currAlert = "";
                try {
                    if (rawAlert && typeof rawAlert === "object") {
                        Object.keys(rawAlert).forEach((key) => {
                            currAlert += key.toString() + " -> " + stringifyAlert(rawAlert[key]).toString() + "\n";
                        });
                    } else if (rawAlert && Array.isArray(rawAlert)) {
                        var cnt = 1;
                        rawAlert.forEach((element) => {
                            currAlert += cnt.toString() + " -> " + stringifyAlert(element).toString() + "\n";
                            cnt += 1;
                        });
                    } else if (typeof rawAlert === "number" || typeof rawAlert === "boolean" || rawAlert instanceof Date) {
                        currAlert = rawAlert.toString();
                    } else if (typeof rawAlert === "string") {
                        currAlert = rawAlert;
                    }
                } catch (err) {
                    let temp = { alert: rawAlert };
                    currAlert = JSON.stringify(temp);
                }
                return currAlert;
            }

            var rawAlert = data.alert;
            var currAlert = stringifyAlert(rawAlert);

            if (data.result === true) {
                window.location.href = data.redirect;
            } else {
                alert(currAlert);
            }

        })
        .catch(error => {
            alert("Something went wrong, Try again after sometime!!!");
            console.error(error);
        });
}


var preExecuted = true;
function chechInputLengthValidity(input, warningLabelId) {
    const warningLabel = document.getElementById(warningLabelId);
    var currExecuted = "nochange";
    var warningMsg = "";
    //console.log(`input ---- length(${input.value.length})`);
    if (input.value.length >= input.maxLength && preExecuted) {
        console.log(`input... reached limit`);
        warningMsg = `Max length ${input.maxLength}`;
        currExecuted = false;
    } else if (!preExecuted) {
        console.log(`input... within limit`);
        currExecuted = true;
    }
    if (currExecuted !== "nochange") {
        warningLabel.innerHTML = warningMsg;
        input.setCustomValidity(warningMsg);
        //if (!input.checkValidity()) {
        //    input.reportValidity();
        //}
        //the above method will give notify, if not used it will be notified at submission only
        preExecuted = currExecuted;
    }
}

function togglePassword(eyeBtnId, passwordFieldId) {
    const eyeBtn = document.getElementById(eyeBtnId);
    const passwordField = document.getElementById(passwordFieldId);

    if (passwordField.type === "password") {
        eyeBtn.setAttribute("class", "eye-slash");
        passwordField.type = "text";
    } else {
        eyeBtn.setAttribute("class", "eye");
        passwordField.type = "password";
    }
}
