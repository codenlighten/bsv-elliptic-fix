import swaggerJsdoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "BSV Key Management API",
      version: "1.0.0",
      description: "A comprehensive Bitcoin SV (BSV) key management system API",
      license: {
        name: "MIT",
        url: "https://opensource.org/licenses/MIT",
      },
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "Development server",
      },
      {
        url: "https://bsv-elliptic-fix-bmf3f.ondigitalocean.app",
        description: "Production server",
      },
    ],
  },
  apis: ["./index.js"], // Path to the API docs
};

const specs = swaggerJsdoc(options);
export default specs;
