import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface ProxyRequest {
  tenant: string;
  token: string;
  endpoint: string;
  method?: string;
  body?: unknown;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 200,
      headers: corsHeaders,
    });
  }

  try {
    const { tenant, token, endpoint, method = "GET", body }: ProxyRequest = await req.json();

    if (!tenant || !token || !endpoint) {
      return new Response(
        JSON.stringify({ error: "Missing required fields: tenant, token, endpoint" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const baseUrl = `https://${tenant}.console.ves.volterra.io`;
    const url = `${baseUrl}${endpoint}`;

    const fetchOptions: RequestInit = {
      method,
      headers: {
        "Authorization": `APIToken ${token}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
    };

    if (body && (method === "POST" || method === "PUT" || method === "PATCH")) {
      fetchOptions.body = JSON.stringify(body);
    }

    const response = await fetch(url, fetchOptions);
    const responseData = await response.json();

    return new Response(
      JSON.stringify(responseData),
      {
        status: response.status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
    return new Response(
      JSON.stringify({ error: errorMessage }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
