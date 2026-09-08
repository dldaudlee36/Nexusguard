document.addEventListener("change", async function (event) {
    const target = event.target;

    if (
        target &&
        target.tagName === "INPUT" &&
        target.type === "file" &&
        target.files &&
        target.files.length > 0
    ) {
        const file = target.files[0];

        console.log("[NexusGuard] FILE_UPLOAD_ATTEMPT");
        console.log("사이트:", window.location.hostname);
        console.log("파일명:", file.name);
        console.log("파일 크기:", file.size);

        const logData = {
            target: window.location.hostname,
            file_name: file.name,
            file_size: file.size
        };

        try {
            const response = await fetch(
                "http://127.0.0.1:8765/upload-event",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(logData)
                }
            );

            if (response.ok) {
                console.log(
                    "[NexusGuard] Agent 전달 성공"
                );
            } else {
                console.log(
                    "[NexusGuard] Agent 오류:",
                    response.status
                );
            }

        } catch (error) {
            console.log(
                "[NexusGuard] Agent 연결 실패:",
                error
            );
        }
    }
});