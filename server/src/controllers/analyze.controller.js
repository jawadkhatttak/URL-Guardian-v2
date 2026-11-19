import { analyzeUrl } from "../services/analysis.service.js";

export async function analyzeController(req, res, next) {
    try {
        const result = await analyzeUrl(req.parsedUrl.href);
        res.status(200).json(result);
    } catch (error) {
        next(error);
    }
}
