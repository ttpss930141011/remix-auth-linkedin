export function redirect(url: string, init: ResponseInit | number = 302) {
	let responseInit = init;

	if (typeof responseInit === "number") {
		responseInit = { status: responseInit, headers: {} };
	} else if (!("status" in responseInit)) {
		responseInit = { ...responseInit, status: 302 };
	}

	let headers = new Headers(responseInit.headers);
	headers.set("Location", url);

	return new Response(null, { ...responseInit, headers });
}
